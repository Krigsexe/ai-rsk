# ai-rsk v0.2.0 - Patch Notes

## New Architecture: Compliance Profiles & Environment Modes

### Profiles System
- New CLI flags: `--gdpr`, `--seo`, `--a11y`, `--ai-act`, `--all`
- Config file support: `profiles: [security, gdpr]`, `region: eu`
- `region: "eu"` in config automatically activates GDPR profile
- `--all` enables all profiles: security + gdpr + ai-act + seo + a11y
- Rules have a `category` field (default: "security") - only loaded when their category's profile is active
- 100% backward compatible: default scan = security only, identical to v0.1.x

### Environment Modes
- New CLI flag: `--mode development|production`
- Config file support: `mode: production`
- Rules can have a `mode` field - only fire in the specified mode
- No mode set = all rules active (default behavior preserved)

### Files Changed
- `src/cli.rs` — 6 new flags on Scan command
- `src/config.rs` — profiles, mode, region fields + resolve_profiles() + resolve_mode()
- `src/rules.rs` — category and mode fields on Rule struct
- `src/main.rs` — profile/mode filtering in scan pipeline, display in output

## New Rules (7)

| Rule | CWE | Severity | Source |
|---|---|---|---|
| `UNPROTECTED_API_ROUTE` | CWE-862 | WARN | DryRun Security 2026: #1 vuln in AI-generated code |
| `MATH_RANDOM_CRYPTO` | CWE-338 | BLOCK | Endor Labs: universal AI pattern |
| `JWT_NO_EXPIRY` | CWE-613 | WARN | DryRun Security: JWT mishandling |
| `SQL_INJECTION_CONCAT` | CWE-89 | BLOCK | CWE #2 2025, #1 AI backend vuln |
| `PATH_TRAVERSAL_FS` | CWE-22 | BLOCK | JFrog Security Research 2025 |
| `ERROR_STACK_LEAK` | CWE-209 | WARN | OWASP A10:2025 |
| `WEAK_HASH_BCRYPT` | CWE-916 | WARN | CrowdStrike 2025 |

## Enriched Test Fixtures

- `tests/fixtures/vulnerable/real-world-patterns.js` — 25+ real-world vulnerable patterns sourced from actual repos (alixia-gen, Ai-Ops) and security research (JFrog, Endor Labs, DryRun, CrowdStrike, OWASP)
- `tests/fixtures/safe/real-world-patterns.js` — corresponding secure implementations
- Individual fixtures for each new rule (vulnerable + safe)

## Validation

- 162 unit tests passing
- Clippy: 0 warnings
- Each new rule individually tested: vulnerable matches, safe doesn't
- All 29 original fixture pairs regression-tested: 0 issues
- 26/39 rules match on comprehensive real-world-patterns.js (13 don't match due to: Python-only targeting, negation satisfaction in mixed files, HTML/JSX patterns not in .js file)

## Stats
- Rules: 32 -> 39 (7 new security rules)
- Tests: 162 passing
- Profiles: security (default), gdpr, ai-act, seo, a11y (ready for future rules)
- Modes: development, production (ready for future mode-specific rules)
