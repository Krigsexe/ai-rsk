# Architecture

ai-rsk is a single Rust binary that orchestrates three layers of security scanning.

## Scan Flow

```
ai-rsk [path]
  |
  +-- 1. DETECT    Identify ecosystems (JS/TS, Python, Go, Rust)
  |                by reading package.json, requirements.txt, go.mod, Cargo.toml
  |
  +-- 2. CHECK     Verify required tools are installed and up to date
  |                (Semgrep, Gitleaks, osv-scanner, knip for JS)
  |
  +-- 3. RUN       Execute external tools, capture output
  |                Threaded pipe reading to prevent deadlocks
  |
  +-- 4. SCAN      Apply 67 built-in YAML rules (Layer 1)
  |                Tree-sitter AST filter for context-aware detection
  |                Agnostic negation: project-wide, not per-file
  |
  +-- 5. ANALYZE   Project structure analysis (Layer 3)
  |                Tests, CI/CD, dead deps, documentation
  |
  +-- 6. REPORT    Security score, findings, markdown report
  |
  +-- 7. EXIT      0 = pass, 1 = blocked, 2 = internal error
```

## Three Layers

### Layer 1 - Built-in Rules (Regex + Tree-sitter AST, offline)
67 YAML rules embedded in the binary via `include_str!`. Each rule has:
- A regex pattern to detect
- Optional negation pattern (checked project-wide)
- CWE reference verified on cwe.mitre.org
- File type filters and path exclusions

Tree-sitter AST filter eliminates false positives in comments and Python docstrings. Regex detects patterns, tree-sitter filters context.

These catch patterns that existing tools miss: tokens in localStorage, missing security headers, client-side auth, Bearer tokens in frontend code, Django/Flask misconfigurations, Python deserialization, SQL injection via f-strings.

### Layer 2 - External Tools
Universal tools (always required):
- **Semgrep** - SAST with 1000+ rules, taint analysis
- **Gitleaks** - Secrets in code and git history
- **osv-scanner** - CVE in dependencies

Ecosystem-specific tools:
- **knip** - Dead code and unused dependency detection (JavaScript/TypeScript)

Recommended tools:
- **rtk** - Token-optimized CLI proxy (60-90% savings)
- **cargo-audit** - Rust dependency vulnerability auditing

ai-rsk manages their installation, updates, and timeout.

### Layer 3 - Project Analysis
Reads project structure to detect:
- Missing tests, CI/CD, documentation
- Dead dependencies, deprecated packages
- Console.log without production stripping
- Duplicate HTTP clients
- Tamper detection (ai-rsk scan || true, --no-verify)
- .env not gitignored, Dockerfile root user

## Source Files

| File | Purpose |
|------|---------|
| `main.rs` | Entry point, CLI dispatch, default command (ai-rsk = ai-rsk scan) |
| `cli.rs` | Argument parsing (scan, init, check, update) |
| `config.rs` | Config file loading (ai-rsk.config.yaml) |
| `detect.rs` | Ecosystem detection (JS, Python, Go, Rust) |
| `rules.rs` | Rule engine, agnostic negation, file scanning, AST integration |
| `runner.rs` | External tool execution, pipe management, timeout |
| `tools.rs` | Tool definitions, version checking, auto-install, GitHub Releases fallback |
| `types.rs` | Shared types (Finding, Severity, Ecosystem, ScanResult, security score, report.md) |
| `analyze.rs` | Project structure analysis (Layer 3) |
| `init.rs` | Project setup (interactive cliclack, LLM discipline for 16 tools, git hooks, prebuild) |
| `embedded_rules.rs` | Compile-time rule embedding (67 include_str!) |
| `ast_filter.rs` | Tree-sitter AST filter (Python, JavaScript/TypeScript) |
| `version.rs` | Version check against crates.io, self-update command |

## Design Principles

- **Deterministic** - Same input = same output. No LLM, no inference, no randomness.
- **Imposition, not discipline** - LLMs don't follow advice. Exit code 1 forces action.
- **Zero runtime dependency** - Single binary. External tools are managed, not bundled.
- **Offline first** - Layer 1 works without network. Layer 2 needs network for rule updates.
- **Self-compliant** - ai-rsk passes its own scan at 100/100.
