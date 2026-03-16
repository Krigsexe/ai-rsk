# ai-rsk v0.6.0 - Patch Notes — Multi-Language + Infrastructure

## New Rules (5 YAML, category: security)
| Rule | CWE | Severity | Language | Source |
|---|---|---|---|---|
| `PICKLE_LOAD` | CWE-502 | BLOCK | Python | CWE-502 Deserialization |
| `YAML_UNSAFE` | CWE-502 | BLOCK | Python | CVE-2020-1747 PyYAML |
| `SUBPROCESS_SHELL` | CWE-78 | BLOCK | Python | CWE Top 25:2025 #5 |
| `TEXT_TEMPLATE_HTML` | CWE-79 | BLOCK | Go | CWE-79 XSS |
| `HTTP_NO_TIMEOUT` | CWE-400 | WARN | Go | CWE-400 Resource Exhaustion |

## New Checks (3 analyze.rs, always active)
| Check | Severity | Detects |
|---|---|---|
| `NO_LOCKFILE` | WARN | No dependency lockfile (package-lock.json, Cargo.lock, go.sum, etc.) |
| `ENV_NOT_GITIGNORED` | BLOCK | .env file exists but not in .gitignore — secrets will be committed |
| `DOCKERFILE_ROOT_USER` | WARN | Dockerfile without USER directive — container runs as root |

## Details
- **PICKLE_LOAD**: Detects pickle.load(), pickle.loads(), cPickle, shelve.open(). #1 Python deserialization vulnerability.
- **YAML_UNSAFE**: Detects yaml.load() with unsafe Loader, yaml.unsafe_load(). Equivalent to eval().
- **SUBPROCESS_SHELL**: Detects subprocess with shell=True, os.system(), os.popen(). CWE Top 25 #5.
- **TEXT_TEMPLATE_HTML**: Detects Go text/template import without html/template. Per-file negation (agnostic_negation: false).
- **HTTP_NO_TIMEOUT**: Detects http.ListenAndServe() without timeout configuration. Slowloris attack vector.
- **NO_LOCKFILE**: Checks for lockfiles matching detected ecosystems. Only warns if an ecosystem that uses lockfiles is detected.
- **ENV_NOT_GITIGNORED**: BLOCK severity — .env with secrets not in .gitignore is a critical security risk.
- **DOCKERFILE_ROOT_USER**: Checks for USER directive in Dockerfile/Containerfile.

## Architecture Changes
- **Dynamic rule count test**: test_load_all_rules now compares disk YAML count with embedded_rules count dynamically — no more hardcoded numbers.
- **SECURITY_RULES.md**: Infra checks added to security checklist (lockfile, .env, Dockerfile USER).

## Stats
- Total YAML rules: 55 (31 original + 24 new)
- Total checks: 18 analyze.rs
- Total detections: 73
- Languages covered: JavaScript/TypeScript, Python, Go, Rust, HTML
- Profiles: security (always), gdpr, ai-act, seo, a11y
