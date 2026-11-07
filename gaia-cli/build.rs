// Compiles the SPARK Ada core (gaia-core-ada) into a static library at build time.
// Requires GNAT (gnatmake) and its adalib; set GNAT=gnatmake / GCC=gcc to override.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let ada = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../gaia-core-ada");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", ada.display());

    // Use the gcc that matches the installed GNAT (gnat-N ships gnat1 only for gcc-N).
    let gcc = std::env::var("GCC").unwrap_or_else(|_| {
        let major = Command::new("gnatmake").arg("--version").output().ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|v| v.split_whitespace().nth(1).map(|s| s.split('.').next().unwrap_or("").to_string()))
            .filter(|m| !m.is_empty());
        match major { Some(m) => format!("gcc-{m}"), None => "gcc".into() }
    });
    let st = Command::new(&gcc)
        .args(["-c", "-O2", "-gnatA"])
        .arg(ada.join("gaia_rules.adb"))
        .current_dir(&out)
        .status()
        .expect("failed to run gcc; install GNAT (e.g. `apt install gnat`)");
    assert!(st.success(), "Ada compilation failed");
    let st = Command::new("ar")
        .args(["rcs", "libgaia_rules.a", "gaia_rules.o"])
        .current_dir(&out)
        .status()
        .expect("ar not found");
    assert!(st.success());

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=gaia_rules");
    if let Ok(o) = Command::new(&gcc).arg("-print-libgcc-file-name").output() {
        if let Ok(p) = String::from_utf8(o.stdout) {
            if let Some(base) = std::path::Path::new(p.trim()).parent() {
                println!("cargo:rustc-link-search=native={}", base.join("adalib").display());
            }
        }
    }
    println!("cargo:rustc-link-lib=static=gnat");
}
