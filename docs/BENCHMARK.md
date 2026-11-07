# GAIA vs gitleaks — honest comparison

Date: 2026-11-07. GAIA v0.2.1 vs gitleaks (latest via `go install`), both on default rules, run with
`gitleaks detect --no-git` and `gaia <dir> --json`. Corpora are public repositories that contain
**intentionally fake** secrets, so no real credentials or personal data were involved.

| Corpus | GAIA findings | gitleaks findings | Same file:line | GAIA only | gitleaks only |
|---|---|---|---|---|---|
| Plazmaz/leaky-repo | 41 | 22 | 22 | 19 | 0 |
| trufflesecurity/test_keys | 3 | 3 | 3 | 0 | 0 |
| OWASP/wrongsecrets | 114 | 54 | 7 | 107 | 47 |

Counts are distinct file:line locations. v0.2.0 numbers were 24/22/11, 2/3/2 and 112/54/15 (computed with a
looser matching method, so the wrongsecrets overlap is not comparable). v0.2.1 added a rule for unquoted
config values and Slack webhooks. Most of the 47 wrongsecrets lines only gitleaks reports are
`generic-api-key` hits on container image tags, which look like false positives.

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
