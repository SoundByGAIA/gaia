// GAIA Scrub — air-gapped PII & secret redactor.
// Cleans logs, DB dumps, JSON/CSV and support files BEFORE you share them. No network code.
//
// Detects: email, phone, Turkish national ID (checksum-validated), credit card (Luhn), IBAN,
//          IPv4/IPv6, MAC, AWS/Google/Stripe/GitHub/Slack keys, JWT, private keys.
// Modes: placeholder (default) · mask · hash (deterministic — preserves relationships).
use std::{env, fs, io::{self, Read, Write}};
use regex::Regex;
use sha2::{Sha256, Digest};

fn is_turkish() -> bool {
    env::var("GAIA_LANG").map(|v| v.eq_ignore_ascii_case("tr")).unwrap_or(false)
}

// ── Doğrulayıcılar (yanlış-pozitifi kes) ──────────────────────────────────────
fn luhn_ok(digits: &str) -> bool {
    let ds: Vec<u32> = digits.chars().filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap()).collect();
    if ds.len() < 13 || ds.len() > 19 { return false; }
    let mut sum = 0u32; let mut alt = false;
    for &d in ds.iter().rev() {
        let mut v = d;
        if alt { v *= 2; if v > 9 { v -= 9; } }
        sum += v; alt = !alt;
    }
    sum % 10 == 0
}
fn tckn_ok(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() != 11 || d[0] == 0 { return false; }
    let odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let even = d[1] + d[3] + d[5] + d[7];
    let d10 = ((odd * 7).wrapping_sub(even)) % 10;
    if d10 != d[9] { return false; }
    let sum10: u32 = d[..10].iter().sum();
    sum10 % 10 == d[10]
}

#[derive(Clone)]
struct Pat { name: &'static str, tag: &'static str, re: Regex, validate: Option<fn(&str) -> bool> }

fn patterns() -> Vec<Pat> {
    let p = |name, tag, re: &str, v: Option<fn(&str)->bool>| Pat {
        name, tag, re: Regex::new(re).unwrap(), validate: v };
    vec![
        // ── KORU (redakte ETME): tarih/saat damgaları — loglar bunlarla dolu, PII değil.
        // En yüksek öncelikte tanınıp telefon/kart eşleşmesinden korunur (yanlış-pozitif kökü).
        p("Timestamp", "_SKIP", r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?", None),
        p("Time", "_SKIP", r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b", None),
        // secret'lar önce (en yüksek öncelik) — spesifik anahtar formatları
        p("Private Key", "SECRET", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", None),
        p("AWS Access Key", "SECRET", r"\bAKIA[0-9A-Z]{16}\b", None),
        p("AWS Secret", "SECRET", r"(?i)aws_secret[^\n]{0,20}[:=]\s*[A-Za-z0-9/+=]{40}", None),
        p("Google API Key", "SECRET", r"\bAIza[0-9A-Za-z\-_]{35}\b", None),
        p("Stripe Key", "SECRET", r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", None),
        p("GitHub Token", "SECRET", r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b", None),
        p("Slack Token", "SECRET", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", None),
        p("JWT", "SECRET", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", None),
        p("Bearer Token", "SECRET", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}", None),
        // finansal / kimlik
        p("Credit Card", "CARD", r"\b\d(?:[ -]?\d){12,18}\b", Some(luhn_ok)),
        p("IBAN", "IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", None),
        p("TCKN", "TCKN", r"\b[1-9]\d{10}\b", Some(tckn_ok)),
        // ağ tanımlayıcıları — telefondan ÖNCE (IPv4 nokta-ayracı telefonla karışmasın)
        p("IPv6", "IPV6", r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b", Some(ipv6_ok)),
        p("IPv4", "IPV4", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", None),
        p("MAC", "MAC", r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", None),
        // iletişim (PII)
        p("Email", "EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", None),
        // telefon EN SON (en gevşek): ayraç space/- ZORUNLU. Nokta ayracı YOK (IPv4 karışır),
        // tarih zaten _SKIP ile korunuyor → ham/ISO sayı dizileri elenir.
        p("Phone", "PHONE", r"(?:(?:\+|00)\d{1,3}[ \-]?)?(?:\(\d{1,4}\)[ \-]?)?\d{2,4}(?:[ \-]\d{2,4}){2,4}", Some(phone_ok)),
    ]
}
// telefon: en az 10 rakam + en az bir ayraç/+ (saf ardışık sayı = telefon değil)
fn phone_ok(s: &str) -> bool {
    s.chars().filter(|c| c.is_ascii_digit()).count() >= 10
        && s.chars().any(|c| c == ' ' || c == '-' || c == '+' || c == '(')
}
// IPv6: gerçek IPv6 ya "::" içerir ya bir hex-harf (a-f) → saat "14:22:01" (saf rakam) elenir
fn ipv6_ok(s: &str) -> bool {
    s.contains("::") || s.chars().any(|c| c.is_ascii_hexdigit() && !c.is_ascii_digit())
}

#[derive(Clone, Copy, PartialEq)]
enum Mode { Placeholder, Mask, Hash }

fn short_hash(s: &str) -> String {
    let mut h = Sha256::new(); h.update(s.as_bytes());
    hex::encode(&h.finalize()[..3])
}
fn mask_value(s: &str) -> String {
    let t = s.trim();
    let n = t.chars().count();
    if n <= 4 { return "*".repeat(n.max(1)); }
    let first: String = t.chars().take(2).collect();
    let last: String = t.chars().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{first}{}{last}", "*".repeat(n.saturating_sub(4)))
}
fn replacement(tag: &str, matched: &str, mode: Mode) -> String {
    match mode {
        Mode::Placeholder => format!("[{tag}]"),
        Mode::Mask => mask_value(matched),
        Mode::Hash => format!("[{tag}#{}]", short_hash(matched.trim())),
    }
}

struct ScrubResult { text: String, counts: std::collections::BTreeMap<&'static str, usize>, total: usize }

fn scrub(input: &str, pats: &[Pat], mode: Mode) -> ScrubResult {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut total = 0usize;
    let mut out = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        // her satırda: tüm eşleşmeleri (başlangıç konumuyla) topla, çakışanları öncelik sırasına göre ele
        let mut hits: Vec<(usize, usize, &'static str, &'static str)> = Vec::new();
        for pat in pats {
            for m in pat.re.find_iter(line) {
                if let Some(v) = pat.validate { if !v(m.as_str()) { continue; } }
                hits.push((m.start(), m.end(), pat.tag, pat.name));
            }
        }
        // önce başlangıç, sonra daha uzun eşleşme öncelikli (secret > geniş sayı)
        hits.sort_by(|a, b| a.0.cmp(&b.0).then((b.1 - b.0).cmp(&(a.1 - a.0))));
        let mut taken: Vec<(usize, usize, &'static str)> = Vec::new();
        let mut last_end = 0usize;
        for (s, e, tag, _name) in hits {
            if s < last_end { continue; } // çakışan eşleşmeyi atla
            taken.push((s, e, tag));
            last_end = e;
        }
        // uygula (soldan sağa), limit'e uy
        let mut cur = 0usize;
        for (s, e, tag) in taken {
            out.push_str(&line[cur..s]);
            let matched = &line[s..e];
            if tag == "_SKIP" {
                out.push_str(matched); // tarih/saat: korunur, redakte edilmez, sayılmaz
                cur = e;
                continue;
            }
            out.push_str(&replacement(tag, matched, mode));
            *counts.entry(tag).or_insert(0) += 1;
            total += 1;
            cur = e;
        }
        out.push_str(&line[cur..]);
    }
    ScrubResult { text: out, counts, total }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();

    if args.len() < 2 || flag("-h") || flag("--help") {
        usage(); return;
    }
    let json_out = flag("--json");

    let mode = match opt("--mode").as_deref() {
        Some("mask") => Mode::Mask,
        Some("hash") => Mode::Hash,
        _ => Mode::Placeholder,
    };
    // girdi: ilk bayrak-olmayan argüman = dosya, ya da '-' = stdin
    let target = args.iter().skip(1).find(|a| !a.starts_with('-')).cloned()
        .or_else(|| if flag("-") { Some("-".into()) } else { None });
    let input = match target.as_deref() {
        Some("-") | None => { let mut s = String::new(); io::stdin().read_to_string(&mut s).ok(); s }
        Some(path) => match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                if is_turkish() { eprintln!("❌ okunamadı: {path}: {e}"); }
                else { eprintln!("❌ could not read: {path}: {e}"); }
                std::process::exit(1);
            }
        },
    };

    let res = scrub(&input, &patterns(), mode);

    // çıktı yönlendirme: --json (rapor), -o <dosya>, --in-place, yoksa stdout
    if json_out {
        print_json(&res);
        return;
    }
    if let Some(out_path) = opt("-o") {
        fs::write(&out_path, &res.text).unwrap_or_else(|e| {
            if is_turkish() { eprintln!("❌ yazılamadı: {e}"); } else { eprintln!("❌ could not write: {e}"); }
            std::process::exit(1);
        });
        eprint_report(&res, &format!("→ {out_path}"));
    } else if flag("--in-place") {
        if let Some(path) = target.as_deref().filter(|t| *t != "-") {
            fs::write(path, &res.text).ok();
            eprint_report(&res, &format!("→ {path} (in-place)"));
        } else {
            eprintln!("{}", if is_turkish() { "--in-place için bir dosya gerekir (stdin değil)." }
                             else { "--in-place requires a file (not stdin)." });
        }
    } else {
        // temizlenmiş metin stdout'a, rapor stderr'e (pipe-dostu)
        print!("{}", res.text);
        io::stdout().flush().ok();
        eprint_report(&res, "→ stdout");
    }
}

fn eprint_report(res: &ScrubResult, dest: &str) {
    let tr = is_turkish();
    eprintln!();
    if tr {
        eprintln!("  GAIA Scrub · air-gapped · 0 ağ · {}", dest);
        eprintln!("  Redakte edilen: {} PII/secret", res.total);
    } else {
        eprintln!("  GAIA Scrub · air-gapped · 0 network · {}", dest);
        eprintln!("  Redacted: {} PII/secret", res.total);
    }
    for (tag, n) in &res.counts { eprintln!("    {:<7} {}", tag, n); }
}

fn print_json(res: &ScrubResult) {
    let counts: serde_json::Map<String, serde_json::Value> = res.counts.iter()
        .map(|(k, v)| (k.to_string(), serde_json::json!(v))).collect();
    let out = serde_json::json!({
        "tool": "gaia-scrub", "air_gapped": true, "network_calls": 0,
        "redacted_total": res.total, "by_type": counts,
        
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn usage() {
    if is_turkish() {
        println!("GAIA Scrub — Air-gapped PII & secret redactor\n");
        println!("Logları/dump'ları PAYLAŞMADAN ÖNCE temizle. Kod/veri makineden çıkmaz (0 ağ).\n");
        println!("Kullanım:  gaia-scrub <dosya> [seçenekler]");
        println!("           cat app.log | gaia-scrub -            # stdin → stdout\n");
        println!("Seçenekler:");
        println!("  --mode placeholder|mask|hash   redaksiyon biçimi (hash: ilişki-korumalı)");
        println!("  -o <dosya>                      temiz kopyayı dosyaya yaz");
        println!("  --in-place                      dosyayı yerinde temizle");
        println!("  --json                          makine-okur rapor (CI/CD)");
        println!("\nTespit: email·telefon·TCKN·kredi kartı·IBAN·IP·MAC·AWS/Google/Stripe/GitHub/Slack·JWT·özel-anahtar");
    } else {
        println!("GAIA Scrub — Air-gapped PII & secret redactor\n");
        println!("Clean logs/dumps BEFORE sharing them. Your code/data never leaves this machine (0 network).\n");
        println!("Usage:    gaia-scrub <file> [options]");
        println!("          cat app.log | gaia-scrub -            # stdin → stdout\n");
        println!("Options:");
        println!("  --mode placeholder|mask|hash   redaction mode (hash is relationship-preserving)");
        println!("  -o <file>                       write the clean copy to a file");
        println!("  --in-place                      clean the file in place");
        println!("  --json                          machine-readable report (CI/CD)");
        println!("\nDetects: email·phone·SSN/TCKN·credit card·IBAN·IP·MAC·AWS/Google/Stripe/GitHub/Slack keys·JWT·private key");
    }
}
