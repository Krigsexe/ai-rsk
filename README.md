<p align="center">
  <strong>ai-rsk - Security gate for AI-generated code</strong>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/Krigsexe/ai-rsk/releases"><img src="https://img.shields.io/badge/Release-v0.1.0-blue.svg" alt="Release v0.1.0"></a>
</p>

<p align="center">
  <a href="#installation">Install</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-it-detects">What it Detects</a> &bull;
  <a href="ARCHITECTURE.md">Architecture</a> &bull;
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---
[![Visitors Badge](https://api.visitorbadge.io/api/VisitorHit?user=Krigsexe&repo=ai-rsk&countColor=%23FFA500)](https://github.com/Krigsexe/ai-rsk)

ai-rsk blocks your build until security issues are fixed. One Rust binary. Three external tools. 31 built-in rules. Your AI can't deploy insecure code because the build won't pass.

## The Problem

LLMs generate functional code, but with recurring security flaws:

```javascript
// LLM writes this - it works, it's insecure
localStorage.setItem('access_token', response.data.token);
fetch('/api/data', { headers: { Authorization: `Bearer ${token}` } });
app.use(cors());
app.use(express.json());
// No helmet, no CSP, no rate limiting, no input validation
```

Non-developers who build with AI ship these patterns to production. Real users' emails, passwords, and payment data become accessible to anyone who knows where to look.

ai-rsk makes this impossible. The build doesn't pass. The LLM is forced to fix the code.

## What Happens When You Run It

```
$ ai-rsk scan

ai-rsk v0.1.0 - Security Gate + Project Analysis
===================================================
  Ecosystems: JavaScript/TypeScript
  ✓ semgrep 1.155.0
  ✓ gitleaks 8.30.0
  ✓ osv-scanner 2.3.3
===================================================

[BLOCK] TOKEN_IN_LOCALSTORAGE (CWE-922)
  File: src/auth.js:42
  Code: localStorage.setItem('access_token', response.data.token)
  Fix:  Move token to HttpOnly cookie server-side.
        res.cookie('token', jwt, { httpOnly: true, secure: true, sameSite: 'strict' });

[BLOCK] Semgrep found security issues.
  ┌──────────────────┐
  │ 11 Code Findings │
  └──────────────────┘

[BLOCK] Gitleaks found secrets in the codebase.
  leaks found: 3

[BLOCK] osv-scanner found known vulnerabilities in dependencies.
  65 packages affected by 97 known vulnerabilities

[WARN] CORS_WILDCARD (CWE-942)
  File: src/app.js:12
  Code: app.use(cors());
  Fix:  Restrict CORS to specific trusted origins.

[WARN] BODY_PARSER_NO_LIMIT (CWE-770)
  File: src/app.js:15
  Code: app.use(express.json());
  Fix:  Add a size limit: app.use(express.json({ limit: '100kb' }));

[ADVISE] No test framework detected.
[ADVISE] No CI/CD pipeline detected.

===================================================
Result: BLOCKED (4B 2W 2A)
Exit code: 1
===================================================
```

The LLM reads this output, fixes every issue, and re-runs the build. It can't skip anything - exit code 1 means the build fails.

## Installation

### Pre-built binaries (recommended)

Download from [Releases](https://github.com/Krigsexe/ai-rsk/releases):

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `ai-rsk-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `ai-rsk-x86_64-apple-darwin.tar.gz` |
| Linux (x64) | `ai-rsk-x86_64-unknown-linux-musl.tar.gz` |
| Linux (ARM64) | `ai-rsk-aarch64-unknown-linux-gnu.tar.gz` |
| Windows (x64) | `ai-rsk-x86_64-pc-windows-msvc.zip` |

```bash
# Linux/macOS example:
tar -xzf ai-rsk-x86_64-unknown-linux-musl.tar.gz
sudo mv ai-rsk /usr/local/bin/

# Windows: extract the zip, add ai-rsk.exe to your PATH
```

### From source (requires Rust 1.85+)

```bash
cargo install --git https://github.com/Krigsexe/ai-rsk
```

### Verify

```bash
ai-rsk --version    # ai-rsk 0.1.0
ai-rsk scan --help  # Show scan options
```

## Quick Start

### 1. Initialize your project

```bash
cd /your/project
ai-rsk init
```

This generates:
- LLM discipline files (compatible with all major AI coding tools)
- `SECURITY_RULES.md` - contract between ai-rsk and the LLM
- Prebuild hook in `package.json` (if present)

### 2. Scan

```bash
ai-rsk scan           # Block on critical issues only
ai-rsk scan --strict  # Block on warnings too
ai-rsk scan --full    # Block on everything (recommended for AI-built projects)
```

### 3. Fix and re-scan

The output tells the LLM exactly what to fix, with code examples. Fix, re-run, repeat until exit code 0.

## What it Detects

### Layer 1 - 31 Built-in Rules (offline, deterministic)

Patterns that LLMs generate repeatedly and existing tools miss:

| Category | Rules | Examples |
|----------|-------|---------|
| **Token/Secret exposure** | 5 | Token in localStorage, Bearer in client code, hardcoded secrets |
| **Missing security headers** | 6 | No helmet, no CSP, no HSTS, no X-Frame-Options, no X-Content-Type |
| **Authentication flaws** | 3 | Client-side auth only, missing rate limiting, WebSocket without auth |
| **Cookie misconfiguration** | 3 | Missing HttpOnly, Secure, SameSite flags |
| **Input/Output** | 5 | eval() with dynamic input, CORS wildcard, SSRF, XSS via dangerouslySetInnerHTML |
| **Business logic** | 3 | Negative price from user input, SELECT * in API response, prompt injection |
| **Infrastructure** | 4 | Source maps in production, body parser without limit, unvalidated redirects |
| **Third-party** | 2 | CDN scripts without SRI, Stripe webhooks without signature verification |

Every rule has a CWE reference verified on [cwe.mitre.org](https://cwe.mitre.org/).

### Layer 2 - External Tools (auto-installed)

| Tool | What it does | Why it matters |
|------|-------------|----------------|
| **[Semgrep](https://semgrep.dev/)** | Static analysis, 1000+ rules, 30+ languages | Catches SQL injection, XSS, SSRF, insecure crypto |
| **[Gitleaks](https://github.com/gitleaks/gitleaks)** | Secret detection in code and git history | API keys, passwords, tokens accidentally committed |
| **[osv-scanner](https://google.github.io/osv-scanner/)** | Known CVE in dependencies | Vulnerable packages that need updating |

These are **automatically installed** if missing. ai-rsk manages their versions and updates.

### Layer 3 - Project Analysis

| Check | Type | What it detects |
|-------|------|-----------------|
| Missing tests | ADVISE | No test framework, no test files |
| Missing CI/CD | ADVISE | No pipeline = security gates can be bypassed |
| Dead dependencies | ADVISE | Installed but never imported |
| Deprecated packages | ADVISE | `request`, `moment`, etc. |
| No console.log stripping | WARN | Console statements leak to production |
| Duplicate HTTP clients | ADVISE | `axios` + `node-fetch` + `got` in same project |

## Severity Levels

| Flag | BLOCK | WARN | ADVISE | Best for |
|------|-------|------|--------|----------|
| `ai-rsk scan` | exit 1 | exit 0 | exit 0 | Senior devs who want security only |
| `ai-rsk scan --strict` | exit 1 | exit 1 | exit 0 | Teams with defense-in-depth |
| `ai-rsk scan --full` | exit 1 | exit 1 | exit 1 | AI-built projects - LLM can't ignore anything |

## Integration

### npm / pnpm / yarn / bun

```json
{
  "scripts": {
    "prebuild": "ai-rsk scan --strict",
    "build": "vite build"
  }
}
```

`prebuild` runs automatically before `build`. Exit code 1 = build stops.

### CI/CD (GitHub Actions)

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ai-rsk
        run: cargo install --git https://github.com/Krigsexe/ai-rsk
      - name: Security gate
        run: ai-rsk scan --strict
```

### Docker (multi-stage)

```dockerfile
# Build stage - ai-rsk scans here
FROM node:20-alpine AS builder
RUN cargo install --git https://github.com/Krigsexe/ai-rsk
COPY . .
RUN ai-rsk scan --strict
RUN npm run build

# Production stage - ai-rsk is NOT here
FROM node:20-alpine
COPY --from=builder /app/dist /app/dist
CMD ["node", "dist/server.js"]
```

## False Positive Handling

```javascript
// ai-rsk-ignore TOKEN_IN_LOCALSTORAGE -- stores UI theme preference, not an auth token
localStorage.setItem('auth_theme_token', 'dark');
```

Rules:
- Comment must be on the **line before** the flagged code
- Justification after `--` is **mandatory** (ignore without reason = still flagged)
- Total ignore count is displayed in the report

## Supported Ecosystems

| Ecosystem | Detection | Layer 1 Rules | Layer 2 Tools | Layer 3 Analysis |
|-----------|-----------|---------------|---------------|------------------|
| JavaScript/TypeScript | `package.json` | 31 rules | Semgrep + Gitleaks + osv-scanner | Full |
| Python | `requirements.txt`, `pyproject.toml` | Partial | Semgrep + Gitleaks + osv-scanner | Tests + CI |
| Go | `go.mod` | Partial | Semgrep + Gitleaks + osv-scanner | Tests + CI |
| Rust | `Cargo.toml` | Partial | Semgrep + Gitleaks + osv-scanner | Tests + CI |

## Why Not Just Use Semgrep?

Semgrep is excellent. ai-rsk uses it. But Semgrep alone doesn't:
- **Force installation** - LLMs skip optional tools
- **Detect absence** - "no helmet" is not a pattern Semgrep finds
- **Block the build** - Semgrep findings don't stop `npm run build`
- **Generate LLM discipline files** - Semgrep doesn't tell your AI coding tool how to behave
- **Analyze project structure** - missing tests, dead deps, no CI

ai-rsk is the orchestrator. Semgrep is one of its tools.

## Philosophy

> There's no such thing as "discipline" with AI. It's about **imposition**.
>
> An LLM will always try to work around the problem to deliver what the user asked for as fast as possible. Security is a brake on that objective - so the LLM will ignore it, work around it, or minimize it.
>
> Every security rule must be **imposed** by a technical mechanism (exit code 1, blocked build, CI that refuses to merge). Advice in stdout is necessary but **insufficient** - only the exit code forces action.

## License

MIT - [Julien GELEE](mailto:julien.gelee@proton.me)

## Support

If ai-rsk helps you ship secure code, consider supporting the project:
- Star this repo
- Report false positives and false negatives
- Contribute rules
- [Fueling my open source work with coffee](https://github.com/sponsors/Krigsexe) 
