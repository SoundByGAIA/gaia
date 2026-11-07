// GAIA Drift-Gate — external API/webhook drift scanner. Extracts API surface, matches a curated
// drift DB, and computes financial risk with a SPARK Ada core. Deterministic, offline, no AI.
use regex::Regex;
use walkdir::WalkDir;
use std::{env, fs};

const DRIFT_DB: &str = include_str!("drift_db.json");
const SKIP_DIRS: &[&str] = &[".git","node_modules","target","vendor","dist","build",".venv","__pycache__","obj",".gnatprove"];

// ── SPARK Ada core: drift -> financial risk/ROI ──
extern "C" {
    fn drift_risk(crit: i32, high: i32, med: i32, watch: i32) -> i32;
    fn drift_dollars_at_risk(crit: i32, high: i32, med: i32) -> i32;
    fn drift_fix_days(crit: i32, high: i32, med: i32) -> i32;
}


fn is_turkish() -> bool { env::var("GAIA_LANG").map(|v| v.eq_ignore_ascii_case("tr")).unwrap_or(false) }

struct Rule { service:String, re:Regex, status:String, replacement:String, severity:String, note:String }
fn load_rules() -> Vec<Rule> {
    let v: serde_json::Value = serde_json::from_str(DRIFT_DB).unwrap_or_else(|e| { eprintln!("❌ drift_db.json is invalid: {e}"); std::process::exit(2); });
    // fail closed: a rule that does not compile must stop the run, never be skipped silently
    v["rules"].as_array().cloned().unwrap_or_default().iter().filter_map(|r| Some(Rule{
        service:r["service"].as_str()?.into(),
        re:Regex::new(r["pattern"].as_str()?).unwrap_or_else(|e| {
            eprintln!("❌ invalid rule pattern for {}: {e}", r["service"]);
            std::process::exit(2);
        }),
        status:r["status"].as_str().unwrap_or("").into(), replacement:r["replacement"].as_str().unwrap_or("").into(),
        severity:r["severity"].as_str().unwrap_or("medium").into(), note:r["note"].as_str().unwrap_or("").into(),
    })).collect()
}
fn api_surface() -> Vec<(&'static str, Regex)> {
    let defs: &[(&str,&str)] = &[
        ("SDK", r"\b(stripe|twilio|paypal|iyzico|sendgrid|firebase|openai|slack|s3|sns|sqs|braintree|square)\b\.\w+"),
        ("Webhook", r#"(req\.body\.\w+|request\.json\[['"]\w+['"]\]|payload\.\w+|event\.data\.\w+)"#),
        ("HTTP", r#"https?://[a-zA-Z0-9.-]+\.(com|io|net|org)/[^\s"')]+"#),
    ];
    defs.iter().filter_map(|(n,p)| Regex::new(p).ok().map(|re| (*n, re))).collect()
}
fn rank(s:&str)->i32{ match s {"critical"=>4,"high"=>3,"medium"=>2,_=>1} }

// ── mock webhook payload generator ──
fn mock_payload(service:&str) -> Option<String> {
    let s = service.to_lowercase();
    let p = match s.as_str() {
        "stripe" => r#"{"id":"evt_test","type":"payment_intent.succeeded","data":{"object":{"id":"pi_test","amount":5000,"currency":"try","status":"succeeded","payment_method":"pm_test"}}}"#,
        "paypal" => r#"{"id":"WH-TEST","event_type":"CHECKOUT.ORDER.APPROVED","resource":{"id":"ORDER-TEST","status":"APPROVED","purchase_units":[{"amount":{"currency_code":"USD","value":"50.00"}}]}}"#,
        "iyzico" => r#"{"iyziEventType":"CHECKOUTFORM_AUTH","paymentId":"12345","conversationId":"conv-test","status":"SUCCESS","paidPrice":"50.00","currency":"TRY"}"#,
        "twilio" => r#"{"MessageSid":"SMtest","MessageStatus":"delivered","To":"+90...","From":"+1...","Body":"test","messagingServiceSid":"MGtest"}"#,
        _ => return None,
    };
    Some(p.to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let json_out = args.iter().any(|a| a=="--json");

    // subcommand: mock <service>
    if args.get(1).map(|s| s.as_str()) == Some("mock") {
        let svc = args.iter().skip(2).find(|a| !a.starts_with("--"));
        match svc.and_then(|s| mock_payload(s)) {
            Some(p) => { println!("// GAIA Drift-Gate — {} test webhook payload:", svc.unwrap()); println!("{p}"); }
            None => println!("{}", if is_turkish() { "Kullanım: gaia-drift mock <stripe|paypal|iyzico|twilio>" }
                                    else { "Usage: gaia-drift mock <stripe|paypal|iyzico|twilio>" }),
        }
        return;
    }

    let target = match args.iter().skip(1).find(|a| !a.starts_with("--")) {
        Some(t)=>t.clone(),
        None=>{
            if is_turkish() {
                println!("GAIA Drift-Gate — harici API/webhook drift tarayıcısı\nKullanım: gaia-drift <dizin> [--json]\n         gaia-drift mock <servis>   ");
            } else {
                println!("GAIA Drift-Gate — external API/webhook drift scanner\nUsage: gaia-drift <directory> [--json]\n       gaia-drift mock <service>   ");
            }
            return;
        }
    };
    let surface = api_surface();
    let rules = load_rules();
    let mut contract=0usize;
    let mut drift: Vec<(String,String,usize,String,String,String,String)> = Vec::new();

    for e in WalkDir::new(&target).into_iter().filter_entry(|e|
        !e.file_name().to_str().map(|n| SKIP_DIRS.contains(&n)).unwrap_or(false)) {
        let e = match e {Ok(e)=>e,Err(_)=>continue};
        if !e.file_type().is_file() { continue; }
        let p = e.path();
        if p.metadata().map(|m| m.len()>1_500_000).unwrap_or(true) { continue; }
        let c = match fs::read_to_string(p){Ok(c)=>c,Err(_)=>continue};
        let rel = p.strip_prefix(&target).unwrap_or(p).display().to_string();
        for (i,line) in c.lines().enumerate() {
            if line.len()>4000 { continue; }
            for (_k,re) in &surface { if re.is_match(line){ contract+=1; } }
            for r in &rules { if r.re.is_match(line){
                drift.push((r.service.clone(),rel.clone(),i+1,r.status.clone(),r.severity.clone(),r.replacement.clone(),r.note.clone())); } }
        }
    }
    drift.sort_by(|a,b| rank(&b.4).cmp(&rank(&a.4)));
    let (mut crit,mut high,mut med,mut watch)=(0,0,0,0);
    for d in &drift { match d.4.as_str(){"critical"=>crit+=1,"high"=>high+=1,"medium"=>med+=1,_=>watch+=1}; }
    let risk = unsafe { drift_risk(crit,high,med,watch) };
    let dollars = unsafe { drift_dollars_at_risk(crit,high,med) };
    let days = unsafe { drift_fix_days(crit,high,med) };

    if json_out {
        let items: Vec<_> = drift.iter().map(|d| serde_json::json!({"service":d.0,"file":d.1,"line":d.2,"status":d.3,"severity":d.4,"replacement":d.5,"note":d.6})).collect();
        let show = items;
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "tool":"GAIA Drift-Gate","airgapped":true,"api_surface":contract,"drift_total":drift.len(),
            "counts":{"critical":crit,"high":high,"medium":med,"watch":watch},
            "risk_score":risk,"daily_dollars_at_risk":dollars,"fix_days":days,"drift":show})).unwrap());
        return;
    }
    let tr = is_turkish();
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    if tr {
        println!("║  GAIA DRIFT-GATE — Harici API Drift & Finansal Risk Raporu    ║");
        println!("║  Kod bu makineden çıkmaz · deterministic · sıfır AI          ║");
    } else {
        println!("║  GAIA DRIFT-GATE — External API Drift & Financial Risk Report ║");
        println!("║  Your code never leaves this machine · deterministic · zero AI║");
    }
    println!("╚══════════════════════════════════════════════════════════════╝");
    if tr {
        println!("  Harici API yüzeyi: {} nokta   |   DRIFT uyumsuzluk: {}", contract, drift.len());
        println!("  🔴 Kritik: {crit}  🟠 Yüksek: {high}  🟡 Orta: {med}  ⚪ İzle: {watch}");
        println!("  ┌─ RİSK SKORU (SPARK core): {risk}/100");
        println!("  ├─ Günlük risk-altındaki iş kaybı: ${dollars}");
        println!("  └─ Tahmini düzeltme: {days} mühendis-günü\n");
    } else {
        println!("  External API surface: {} point(s)   |   DRIFT mismatches: {}", contract, drift.len());
        println!("  🔴 Critical: {crit}  🟠 High: {high}  🟡 Medium: {med}  ⚪ Watch: {watch}");
        println!("  ┌─ RISK SCORE (SPARK core): {risk}/100");
        println!("  ├─ Daily business loss at risk: ${dollars}");
        println!("  └─ Estimated fix: {days} engineer-day(s)\n");
    }
    let lim = drift.len();
    for d in drift.iter().take(lim) {
        let ic = match d.4.as_str(){"critical"=>"🔴","high"=>"🟠","medium"=>"🟡",_=>"⚪"};
        println!("  {ic} [{} · {}] {}:{}", d.0, d.3.to_uppercase(), d.1, d.2);
        println!("      {} {} {}", d.6, if tr { "→ öneri:" } else { "→ suggestion:" }, d.5);
    }
    if drift.is_empty() { println!("  {}", if tr { "✅ Bilinen drift/deprecation yok." } else { "✅ No known drift/deprecation." }); }
    if tr {
        println!("\n  Not: küratörlü drift-DB ({} kural, v{}) offline eşleştirme — kehanet değil kürasyon.",
                 rules.len(), serde_json::from_str::<serde_json::Value>(DRIFT_DB).ok().and_then(|v| v["version"].as_str().map(String::from)).unwrap_or_default());
    } else {
        println!("\n  Note: curated drift-DB ({} rule(s), v{}) offline matching — curation, not divination.",
                 rules.len(), serde_json::from_str::<serde_json::Value>(DRIFT_DB).ok().and_then(|v| v["version"].as_str().map(String::from)).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_rule_in_the_db_compiles() {
        let v: serde_json::Value = serde_json::from_str(super::DRIFT_DB).expect("drift_db.json parses");
        for r in v["rules"].as_array().expect("rules array") {
            let p = r["pattern"].as_str().expect("pattern is a string");
            regex::Regex::new(p).unwrap_or_else(|e| panic!("rule {} does not compile: {e}", r["service"]));
        }
    }
}
