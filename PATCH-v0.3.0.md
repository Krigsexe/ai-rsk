# ai-rsk v0.3.0 - Patch Notes

## RGPD/GDPR Compliance Module

### New Rules (4 YAML)
| Rule | CWE | Severity | Category | Source |
|---|---|---|---|---|
| `TRACKING_NO_CONSENT` | CWE-359 | BLOCK | gdpr | ePrivacy Directive Art.5(3) + RGPD Art.6 |
| `PII_IN_LOCALSTORAGE` | CWE-922 | WARN | gdpr | RGPD Art.5(1)(f) + CNIL guidelines |
| `MISSING_REFERRER_POLICY` | CWE-200 | WARN | security | OWASP Secure Headers Project |
| `MISSING_PERMISSIONS_POLICY` | CWE-1021 | WARN | security | OWASP Top 10:2025 A02 |

### New Checks (2 analyze.rs)
| Check | Severity | Category | Detects |
|---|---|---|---|
| `NO_COOKIE_BANNER` | WARN | gdpr | Tracking scripts present without CMP |
| `NO_PRIVACY_PAGE` | ADVISE | gdpr | No privacy policy page found |

### TRACKING_NO_CONSENT (BLOCK, gdpr)
- Detects: gtag('config'), gtag('event'), fbq('init'), fbq('track'), _paq.push, hotjar.com, GoogleAnalyticsObject, googletagmanager.com/gtm.js
- Negation: CookieBot, OneTrust, CookieYes, tarteaucitron, Klaro, Osano, Didomi, Axeptio, gtag('consent'), fbq('consent')
- Agnostic negation: true (one CMP protects the whole site)

### PII_IN_LOCALSTORAGE (WARN, gdpr)
- Detects: localStorage/sessionStorage.setItem/getItem with PII keys (email, phone, firstName, lastName, address, ssn, dob, birthday, etc.)
- Case insensitive, multilingual (English + French: prenom, nom_famille, adresse, date_naissance, numero_secu)
- Does NOT trigger on non-PII keys (theme, lang, cart, sidebar_collapsed)

### NO_COOKIE_BANNER (WARN, gdpr)
- Project-level check: if tracking scripts exist but no CMP is found
- Detects CMP via: file content patterns (30+ CMP names/components) + package.json dependencies
- Complementary to TRACKING_NO_CONSENT: rule catches per-file violations, check catches project-level absence

### NO_PRIVACY_PAGE (ADVISE, gdpr)
- Checks for: files named privacy/privacy-policy/politique-de-confidentialite/datenschutz/mentions-legales + links to /privacy in source files
- Multilingual: English, French, German, Spanish

### MISSING_REFERRER_POLICY (WARN, security)
- Negation rule: server code without Referrer-Policy header
- Satisfied by: helmet(), manual Referrer-Policy header, referrerPolicy setting
- OWASP recommends strict-origin-when-cross-origin

### MISSING_PERMISSIONS_POLICY (WARN, security)
- Negation rule: server code without Permissions-Policy header
- Satisfied by: helmet(), manual Permissions-Policy/Feature-Policy header
- Only 4% of websites implement this (NATO/Spanish JCDC study)

## Interactive Init with cliclack

### Setup Questionnaire
- `ai-rsk init` presents interactive terminal interface with shield logo + AI-RSK figlet block text
- Orange bordered panel with dynamic version (`env!("CARGO_PKG_VERSION")`)
- MultiSelect: GDPR/RGPD, EU AI Act, SEO, Accessibility
- Select: environment mode (Auto, Development, Production)
- Confirm: EU region (auto-activates GDPR)
- Non-interactive fallback for CI/piped input

### Config Generation
- Generates `ai-rsk.config.yaml` with selected profiles, mode, region
- Documented with comments and examples

### Profile-Aware LLM Files
- `SECURITY_RULES.md` now includes conditional sections per active profile (GDPR, AI Act, SEO, a11y)
- LLM discipline file (CLAUDE.md, .cursorrules, etc.) includes profile-specific rules
- GDPR section lists: TRACKING_NO_CONSENT, PII_IN_LOCALSTORAGE, NO_COOKIE_BANNER, NO_PRIVACY_PAGE
- AI Act section lists: labeling, system prompt protection, audit logging, token limits
- SEO section lists: robots.txt, sitemap, meta viewport, canonical URLs
- a11y section lists: img alt, html lang, form labels

## Architecture Changes

### analyze.rs
- `analyze_project()` now receives `active_profiles` parameter
- GDPR checks (NO_COOKIE_BANNER, NO_PRIVACY_PAGE) conditionally run only when gdpr profile is active
- Ready for future SEO/a11y checks (v0.5.0)

### Version Handling
- All version displays now use `env!("CARGO_PKG_VERSION")` — zero hardcoded version strings
- Affects: main.rs (banner), types.rs (report.md), init.rs (SECURITY_RULES.md, discipline file)

### Code Quality
- Clippy: 0 warnings (saturating_sub fix in init.rs)
- Removed duplicate "privacy-policy" pattern in analyze.rs
- Removed obsolete comment "21 YAML rules" in rules.rs
- Alphabetical order enforced in embedded_rules.rs

## Files Changed
| File | Change |
|---|---|
| `Cargo.toml` | cliclack 0.4, console 0.15 |
| `src/init.rs` | Interactive setup, profile-aware SECURITY_RULES.md + discipline, saturating_sub fix, version dynamic |
| `src/analyze.rs` | active_profiles param, check_cookie_banner(), check_privacy_page(), duplicate removal |
| `src/main.rs` | Pass active_profiles to analyze_project, version dynamic |
| `src/types.rs` | Version dynamic in report.md |
| `src/rules.rs` | Rule count 39→43, obsolete comment removed |
| `src/embedded_rules.rs` | +4 entries (tracking-no-consent, pii-in-localstorage, missing-referrer-policy, missing-permissions-policy), alphabetical reorder |
| `rules/` | +4 YAML files |
| `tests/fixtures/` | +10 fixture files (vulnerable + safe for each new rule) |
| `assets/` | logo-composite.ans, logo-30col.ans |

## Validation
- 167 unit tests passing (162 → 167: +5 profile-aware tests)
- Clippy: 0 warnings
- Build release: OK
- Functional tests: each rule verified (fire/no-fire/safe) on temp directories
- Full source audit: all 10 .rs files read line by line, no dead code, no duplicates, no hardcoded versions

## Stats
- Rules: 39 → 43 YAML (+4)
- Checks: 10 → 12 analyze.rs (+2)
- Total detections: 51 → 55
- Tests: 167 passing
- Profiles: security (always), gdpr (new rules), ai-act/seo/a11y (ready for v0.4.0+)
