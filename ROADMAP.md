# Roadmap

## Vision

ai-rsk must become an impassable wall. The AI has no room to maneuver: it follows the rules or the build fails. The goal is that the AI says "I cannot do anything more than follow your instructions." ai-rsk scans itself: ai-rsk passes its own scan at 100/100.

## Current: v0.7.1

- 67 YAML rules (JS/TS, Python, Go, HTML)
- Tree-sitter AST filter (Python, JavaScript/TypeScript)
- 4 external tools (Semgrep, Gitleaks, osv-scanner, knip)
- 5 compliance profiles (security, GDPR, AI Act, SEO, accessibility)
- Security Score (0-100)
- Default command (`ai-rsk` = `ai-rsk scan`)
- Self-update (`ai-rsk update`)
- Self-compliant (PASS 100/100 on itself)

## v0.8.0: Go deep coverage

- Issue #3: Gorilla, Gin, Echo, standard library patterns
- Go-specific Layer 1 rules

## v0.9.0: Rust rules + Tree-sitter improvements

- Issue #4: Rust rules (unsafe, panic, unwrap, todo, allow dead_code)
- Issue #5: Tree-sitter AST layer improvements (prerequisite for anti-evasion)

## v1.0.0: Quality gate + Anti-evasion

- Issue #6: SBOM generation CycloneDX/SPDX (Cyber Resilience Act compliance)
- Issue #7: Gamedev profile
- Issue #8: Desktop profile
- Issue #9: Mobile profile
- **Issue #16: ANTI-EVASION** (critical objective)
  - String obfuscation detection
  - ai-rsk-ignore abuse detection
  - Variable indirection / dynamic property access
  - Dataflow analysis for semantic equivalents
  - The AI cannot bypass ai-rsk

## v2.0.0: Runtime + Governance

- Issue #10: Runtime monitoring / drift detection
- Issue #11: Agent control plane
- Issue #12: Data governance / privacy flows

## Documentation

- Issue #14: Wiki FAQ
- Issue #15: Manifesto "Why ai-rsk exists"

## Decision

v1.0.0 = the AI can no longer bypass ai-rsk. Non-negotiable.
