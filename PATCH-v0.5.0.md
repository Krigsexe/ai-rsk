# ai-rsk v0.5.0 - Patch Notes — SEO + Accessibility

## New Rules (3 YAML, category: a11y)
| Rule | CWE | Severity | Source |
|---|---|---|---|
| `IMG_NO_ALT` | CWE-1059 | WARN | WCAG 2.2 SC 1.1.1 |
| `NO_HTML_LANG` | CWE-1059 | WARN | WCAG 2.2 SC 3.1.1 |
| `FORM_NO_LABEL` | CWE-1059 | WARN | WCAG 2.2 SC 1.3.1 + 4.1.2 |

## New Checks (4 analyze.rs, category: seo)
| Check | Severity | Detects |
|---|---|---|
| `NO_ROBOTS_TXT` | ADVISE | No robots.txt file found |
| `ROBOTS_EXPOSES_SENSITIVE` | WARN | robots.txt reveals sensitive paths (/admin, /api) |
| `NO_SITEMAP` | ADVISE | No sitemap.xml found |
| `NO_META_VIEWPORT` | ADVISE | HTML files without meta viewport tag |
| `NO_CANONICAL` | ADVISE | HTML files without canonical URL tag |

## Details
- **IMG_NO_ALT**: Detects `<img>` tags without alt attribute or with empty alt. Covers HTML, JSX, TSX, Vue, Svelte.
- **NO_HTML_LANG**: Detects `<html>` tags without lang attribute. HTML files only.
- **FORM_NO_LABEL**: Detects form inputs without label, aria-label, or aria-labelledby. Uses negation to check project-wide for any labeling mechanism.
- **SEO checks**: Only run when --seo profile is active. Check for robots.txt, sitemap.xml, meta viewport, canonical URLs.

## SECURITY_RULES.md Liaison
- SEO section lists all 5 check IDs. a11y section lists all 3 rule IDs.
- Both sections include run commands (`ai-rsk scan --seo`, `ai-rsk scan --a11y`).

## Compliance
- WCAG 2.2 Level A (all 3 a11y rules). ADA Title II effective April 2026. European Accessibility Act.
