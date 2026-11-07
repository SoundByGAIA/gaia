# GAIA

A family of air-gapped developer-security tools, all Apache-2.0, none with network code:

| Tool | What it does |
|---|---|
| `gaia` | secret scanner + risk score |
| `gaia-drift` | finds deprecated/removed third-party API usage (Stripe, PayPal, Twilio, OpenAI, ...) via a curated offline rule DB; `gaia-drift mock <service>` prints test webhook payloads |
| `gaia-scrub` | redacts PII and secrets from logs/dumps before you share them (`placeholder`, `mask`, `hash` modes) |

`gaia-drift`'s rule DB (`gaia-drift/src/drift_db.json`) is hand-curated and incomplete; PRs welcome.

## gaia (scanner)

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
cargo build --release          # override the compiler with GCC=gcc-N if auto-detection fails
./target/release/gaia ./src
./target/release/gaia . --json --fail-on-findings
```

Re-run the proof: `cd gaia-core-ada && gnatprove -P gaia_rules.gpr --level=2` (needs SPARK).

## GitHub Action

```yaml
- uses: SoundByGAIA/gaia@v0.2.0
  with:
    path: .
```

It downloads the checksum-verified release binary (falls back to building from source).

```yaml
# example: fail PRs that add secrets
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SoundByGAIA/gaia@v0.2.0
```

## Comparison

See [docs/BENCHMARK.md](docs/BENCHMARK.md) for an honest side-by-side with gitleaks.

## Scope and limits

Regex-based; it will have false positives and misses. It is not a replacement for a full SAST suite. The
risk score and "engineer-days / dollars saved" figures are heuristics, not measurements.

## Commercial

Source is Apache-2.0. Paid options (support, custom rule packs, one-off security audits): https://soundbygaia.com

## License

Apache-2.0 — see [LICENSE](LICENSE).
