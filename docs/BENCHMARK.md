# GAIA vs gitleaks — honest comparison

Date: 2026-11-07. GAIA v0.2.0 vs gitleaks (latest via `go install`), both on default rules, run with
`gitleaks detect --no-git` and `gaia <dir> --json`. Corpora are public repositories that contain
**intentionally fake** secrets, so no real credentials or personal data were involved.

| Corpus | GAIA findings | gitleaks findings | Same file:line | GAIA only | gitleaks only |
|---|---|---|---|---|---|
| Plazmaz/leaky-repo | 24 | 22 | 11 | 13 | 11 |
| trufflesecurity/test_keys | 2 | 3 | 2 | 0 | 1 |
| OWASP/wrongsecrets | 112 | 54 | 15 | 97 | 39 |

## How to read this

- There are **no ground-truth labels**, so these are counts and overlap, not precision or recall.
  "GAIA only" does not mean false positive, and "gitleaks only" does not mean GAIA is wrong; each tool
  has rules the other lacks.
- GAIA has 7 generic rules. gitleaks ships well over 100 provider-specific rules, so it detects many
  token formats GAIA does not.
- GAIA's broader generic rules (hardcoded `password = "..."`, high-entropy strings) fire more often,
  mostly in files like docs, config samples and tests. Expect more noise from GAIA on training repos.
- Where GAIA is different: a single dependency-free binary, no network code (check with `strace`), masked
  output, and a small SPARK-proved risk core. If you need broad provider coverage or git-history
  scanning, use gitleaks or trufflehog.

## Reproduce

```bash
git clone --depth 1 https://github.com/OWASP/wrongsecrets
./target/release/gaia wrongsecrets --json | jq .findings_total
gitleaks detect --no-git --source wrongsecrets --report-format json --report-path /tmp/gl.json
```
