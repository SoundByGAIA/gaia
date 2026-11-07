# GAIA

Air-gapped code security scanner. It finds hardcoded secrets (private keys, cloud/API tokens,
JWTs, passwords, high-entropy strings) and reports a risk score. Your code never leaves the machine.

- **No network code.** Verify it yourself: `strace -f -e trace=network ./target/release/gaia .` prints no network syscalls.
- **SPARK-proved core.** Risk/ROI arithmetic lives in `gaia-core-ada/` (SPARK Ada). `gnatprove` proves absence of
  run-time errors (overflow, range, division). Proof output: [`SPARK_PROOF.txt`](gaia-core-ada/SPARK_PROOF.txt).
- **Masked output.** Findings show only the first 4 and last 2 characters of a match.
- **CI-friendly.** `--json` for machines, `--fail-on-findings` exits 1 when anything is found.

## Build

Requires Rust and GNAT (`apt install gnat`).

```bash
cargo build --release          # if your gnat is gcc-14: GCC=gcc-14 cargo build --release
./target/release/gaia ./src
./target/release/gaia . --json --fail-on-findings
```

Re-run the proof: `cd gaia-core-ada && gnatprove -P gaia_rules.gpr --level=2` (needs SPARK).

## GitHub Action

```yaml
- uses: SoundByGAIA/gaia@main
  with:
    path: .
```

## Scope and limits

Regex-based; it will have false positives and misses. It is not a replacement for a full SAST suite. The
risk score and "engineer-days / dollars saved" figures are heuristics, not measurements.

## Commercial

Source is Apache-2.0. Paid options (support, custom rule packs, signed drift reports,
one-off security audits): https://soundbygaia.com

## License

Apache-2.0 — see [LICENSE](LICENSE).
