# ai-rsk v0.7.1 - Patch Notes - UX, Pedagogy, Self-Scan

## Summary

This patch makes ai-rsk simpler to use for developers and non-developers, more pedagogical in its output, and self-compliant (ai-rsk passes its own scan at 100/100).

## New Features

### Default command: `ai-rsk` = `ai-rsk scan`
- Running `ai-rsk` without any subcommand now scans the current directory.
- No need to type `ai-rsk scan` unless passing options.
- `ai-rsk --help` and `ai-rsk --version` still work as expected.
- File: `src/main.rs` - fallback on `MissingSubcommand` / `DisplayHelpOnMissingArgumentOrSubcommand` error kinds, injects `"scan"` into args and reparses.

### `ai-rsk update` command
- New subcommand to update ai-rsk to the latest version.
- Checks crates.io for the latest version, compares with current.
- If newer: tries `cargo install ai-rsk` first, falls back to GitHub Releases binary download.
- If up to date: prints confirmation and exits.
- The version check notification (`check_for_update()`) now says `Run: ai-rsk update` instead of `cargo install ai-rsk`.
- Files: `src/cli.rs` (new `Update` variant), `src/version.rs` (new `run_self_update()` function), `src/main.rs` (handler).

### Security Score (0-100)
- Every scan now displays a security score: `Security Score: 72/100`.
- Formula: `100 - (BLOCK * 15 + WARN * 5 + ADVISE * 1)`, floor at 0.
- Color-coded: green (80+), yellow (50-79), red (0-49).
- Present in terminal output, JSON output (`security_score` field), and `report.md`.
- File: `src/types.rs` (new `security_score()` method), `src/main.rs` (display).

### Guided next steps after scan
- After displaying findings, ai-rsk now tells the user what to do:
  - "Fix the 3 BLOCK findings first - the build is blocked until they are resolved."
  - "Then address the 2 WARNs (they become BLOCK with --strict)."
  - "After fixing, run `ai-rsk scan` to verify."
- On PASS: "All clear. Report saved to .ai-rsk/report.md"
- File: `src/main.rs` (guidance block after result display).

### CWE links to official references
- Each finding with CWE identifiers now displays a direct link to cwe.mitre.org.
- Terminal: `Ref: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)`
- report.md: `[CWE-89](https://cwe.mitre.org/data/definitions/89.html)` (clickable markdown link).
- No hardcoded descriptions - the CWE database is the source of truth.
- Files: `src/main.rs` (terminal display), `src/types.rs` (report.md generation).

### Scan progress indicators
- Static messages replaced with numbered steps:
  - `[1/3] Running external tools...`
  - `[2/3] Scanning 58 rules...`
  - `[3/3] Analyzing project structure...`
- File: `src/main.rs`.

### Improved help with examples
- `ai-rsk --help` now shows:
  - Quick start guide (3 steps)
  - "No subcommand needed" note
  - Concrete examples for every command
- `ai-rsk scan --help` shows usage examples and a tip about the default command.
- `ai-rsk init --help`, `ai-rsk check --help`, `ai-rsk update --help` all have context.
- `about` changed from "AI Rust Security Keeper" to "Security gate for AI-generated code. Scans, blocks, and educates."
- File: `src/cli.rs` (clap `after_help` attributes on each command).

## Self-Scan Compliance

ai-rsk now passes its own scan at **100/100** (PASS, 0B 0W 0A).

### Semgrep false positives (documented, excluded in config)
Semgrep's `rust.actix` ruleset flagged 6 findings in ai-rsk's source code:
- 5x `rust.actix.path-traversal.tainted-path` in config.rs, init.rs, rules.rs
- 1x `rust.actix.command-injection` in runner.rs

**Why these are false positives:** ai-rsk is a CLI tool, not an Actix web server. All file paths come from the user's CLI arguments on their own machine (not network input). All binary names in `Command::new()` are hardcoded strings in `tools.rs`, not user-supplied input.

**Resolution:** Excluded via `ai-rsk.config.yaml` with `semgrep_exclude_rules`. The config file includes the justification.

### Gitleaks false positives (documented, excluded in .gitleaksignore)
Gitleaks detected 3 "secrets" in the codebase:
- 1x `stripe-access-token` in `tests/fixtures/vulnerable/real-world-patterns.js:25` - a fake Stripe token (`sk_test_51ABC123...`) used as a test fixture to verify ai-rsk detects secrets.
- 2x `generic-api-key` in `rules/hardcoded-secret.yaml:40,55` - fake API keys used as examples in the YAML rule documentation.

**Why these are false positives:** These are test fixtures and documentation examples by design. They are not real secrets.

**Resolution:** Excluded via `.gitleaksignore` with fingerprints. Each entry has a comment explaining why.

### cargo-audit
Installed cargo-audit (recommended tool for Rust projects). ai-rsk now detects and lists it.

### New files
- `ai-rsk.config.yaml` - ai-rsk configuration for the ai-rsk project itself
- `.gitleaksignore` - Gitleaks false positive exclusions with justifications

## Tests Performed

### Automated
| Test | Result |
|---|---|
| `cargo test` | 187 passed, 0 failed |
| `cargo clippy` | 0 warnings |
| `cargo build --release` | success |

### Functional (manual, on release binary)
| Test | Input | Expected | Result |
|---|---|---|---|
| Default command | `ai-rsk` (no args) | Scans current directory | PASS |
| Help | `ai-rsk --help` | Quick start + examples | PASS |
| Version | `ai-rsk --version` | Shows version | PASS |
| Scan help | `ai-rsk scan --help` | Examples + tip | PASS |
| Update (no network) | `ai-rsk update` | "Could not reach crates.io" message | PASS |
| JSON output | `ai-rsk scan --json` | `security_score` field present | PASS |
| Self-scan | `ai-rsk scan` on ai-rsk | PASS 100/100, 0B 0W 0A | PASS |
| Real project scan | `ai-rsk scan` on ai-alixia | BLOCKED with findings (expected) | PASS |

### New unit tests (3 added)
- `test_security_score_perfect` - 0 findings = 100/100
- `test_security_score_with_findings` - 2B + 1W + 3A = 62/100
- `test_security_score_floor_at_zero` - 10B = 0/100 (not negative)

## Stats
- Total tests: 187 (184 previous + 3 new)
- 0 clippy warnings
- Self-scan: PASS 100/100
