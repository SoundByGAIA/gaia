// GAIA — Air-gapped Code Security Scanner
// Scans a directory for secrets and insecure patterns locally. The scanner has no
// network code. Rust handles parsing/IO; a SPARK Ada core computes risk and ROI.

use regex::Regex;
use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;
use walkdir::WalkDir;

extern "C" {
    fn gaia_risk_score(crit: i32, high: i32, med: i32, low: i32) -> i32;
    fn gaia_engineer_days_saved(crit: i32, high: i32, med: i32, low: i32, files: i32) -> i32;
    fn gaia_dollars_saved(days: i32, crit: i32) -> i32;
}

struct Rule {
    name: &'static str,
    kind: i32, // 4=critical 3=high 2=medium
    re: Regex,
}

struct Finding {
    file: String,
    line: usize,
    rule: &'static str,
    kind: i32,
    masked: String,
}

fn rules() -> Vec<Rule> {
    let defs: &[(&str, i32, &str)] = &[
        ("Private Key", 4, r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        ("AWS Access Key", 4, r"AKIA[0-9A-Z]{16}"),
        ("Google API Key", 3, r"AIza[0-9A-Za-z_\-]{35}"),
        ("Slack Token", 3, r"xox[baprs]-[0-9A-Za-z-]{10,}"),
        ("JWT Token", 3, r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        ("Hardcoded Secret", 3, r#"(?i)(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\s*[:=]\s*["'][^"']{8,}["']"#),
        ("High-Entropy String", 2, r#"["'][A-Za-z0-9+/]{40,}={0,2}["']"#),
    ];
    defs.iter()
        .filter_map(|(n, k, p)| Regex::new(p).ok().map(|re| Rule { name: n, kind: *k, re }))
        .collect()
}

// Findings never print the full secret: first 4 and last 2 characters only.
fn mask(s: &str) -> String {
    let c: Vec<char> = s.trim().chars().collect();
    if c.len() <= 8 {
        return "*".repeat(c.len());
    }
    let head: String = c.iter().take(4).collect();
    let tail: String = c[c.len() - 2..].iter().collect();
    format!("{head}…{tail} ({} chars)", c.len())
}

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "vendor", "dist", "build", ".venv",
    "__pycache__", "obj", ".gnatprove", "coverage", ".next", "out", ".cache", "bin", "gnatprove"];

// Build artifacts and binaries are not scanned (false-positive source).
const SKIP_EXTS: &[&str] = &["s", "o", "a", "so", "dll", "exe", "obj", "map", "lock",
    "png", "jpg", "jpeg", "gif", "pdf", "zip", "gz", "wasm", "ttf", "woff", "woff2", "ico"];

fn skip_by_ext(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(".min.js") {
        return true;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => SKIP_EXTS.contains(&ext.to_lowercase().as_str()),
        None => false,
    }
}

fn usage() {
    println!("GAIA — Air-gapped Code Security Scanner\n");
    println!("Usage:    gaia <directory-to-scan> [--json] [--fail-on-findings]");
    println!("Example:  gaia ./src");
    println!("          gaia . --json --fail-on-findings   # CI gate (exit 1 on findings)");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let json_out = args.iter().any(|a| a == "--json");
    let fail_on_findings = args.iter().any(|a| a == "--fail-on-findings");

    let target = match args.iter().skip(1).find(|a| !a.starts_with("--")) {
        Some(t) => t.clone(),
        None => {
            usage();
            return;
        }
    };

    let rs = rules();
    let mut findings: Vec<Finding> = Vec::new();
    let mut files_scanned = 0usize;

    for entry in WalkDir::new(&target).into_iter().filter_entry(|e| {
        !e.file_name().to_str().map(|n| SKIP_DIRS.contains(&n)).unwrap_or(false)
    }) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if !entry.file_type().is_file() { continue; }
        let path = entry.path();
        if skip_by_ext(path) { continue; }
        if path.metadata().map(|m| m.len() > 1_500_000).unwrap_or(true) { continue; }
        let content = match fs::read_to_string(path) { Ok(c) => c, Err(_) => continue };
        files_scanned += 1;
        for (i, line) in content.lines().enumerate() {
            if line.len() > 4000 { continue; }
            for rule in &rs {
                if let Some(m) = rule.re.find(line) {
                    findings.push(Finding {
                        file: rel(path, &target),
                        line: i + 1,
                        rule: rule.name,
                        kind: rule.kind,
                        masked: mask(m.as_str()),
                    });
                }
            }
        }
    }

    let (mut crit, mut high, mut med, mut low) = (0i32, 0i32, 0i32, 0i32);
    for f in &findings {
        match f.kind { 4 => crit += 1, 3 => high += 1, 2 => med += 1, _ => low += 1 };
    }

    // The Ada core requires inputs in 0..=10_000_000 (SPARK precondition); clamp so the
    // contract holds at run time and the formal proof's assumption is met.
    let cl = |x: i32| x.clamp(0, 10_000_000);
    let (crit, high, med, low) = (cl(crit), cl(high), cl(med), cl(low));
    let files_c = files_scanned.min(10_000_000) as i32;
    let risk = unsafe { gaia_risk_score(crit, high, med, low) };
    let days = cl(unsafe { gaia_engineer_days_saved(crit, high, med, low, files_c) });
    let dollars = unsafe { gaia_dollars_saved(days, crit) };

    if json_out {
        print_json(&findings, files_scanned, crit, high, med, low, risk, days, dollars);
    } else {
        print_report(&findings, files_scanned, crit, high, med, low, risk, days, dollars);
    }
    if fail_on_findings && !findings.is_empty() {
        exit(1);
    }
}

fn rel(p: &Path, base: &str) -> String {
    p.strip_prefix(base).unwrap_or(p).display().to_string()
}

fn print_report(f: &[Finding], files: usize, crit: i32, high: i32, med: i32, low: i32,
                risk: i32, days: i32, dollars: i32) {
    println!("\nGAIA — air-gapped code security report");
    println!("Files scanned: {files}   Total findings: {}", f.len());
    println!("Critical: {crit}   High: {high}   Medium: {med}   Low: {low}");
    println!("Risk score (SPARK core): {risk}/100");
    println!("Estimated engineer-days saved: {days}   Estimated savings: ${dollars}\n");
    for fd in f {
        let sev = match fd.kind { 4 => "CRIT", 3 => "HIGH", 2 => "MED ", _ => "LOW " };
        println!("  [{sev}] [{}] {}:{}  ->  {}", fd.rule, fd.file, fd.line, fd.masked);
    }
    println!();
}

fn print_json(f: &[Finding], files: usize, crit: i32, high: i32, med: i32, low: i32,
              risk: i32, days: i32, dollars: i32) {
    let items: Vec<_> = f.iter().map(|fd| serde_json::json!({
        "rule": fd.rule, "file": fd.file, "line": fd.line, "severity": fd.kind, "match": fd.masked
    })).collect();
    let out = serde_json::json!({
        "tool": "GAIA", "airgapped": true, "files_scanned": files,
        "findings_total": f.len(),
        "counts": {"critical": crit, "high": high, "medium": med, "low": low},
        "risk_score": risk, "engineer_days_saved": days, "dollars_saved": dollars,
        "findings": items
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
