# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ai-rsk, please report it responsibly.

**Email:** julien.gelee@proton.me

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

I will respond within 48 hours and work on a fix promptly.

## Scope

ai-rsk is a security scanning tool. Vulnerabilities in ai-rsk itself are especially critical because they could undermine the security of projects that depend on it.

The following are in scope:
- Rule bypass (a pattern that should be detected but isn't)
- False negatives (a real vulnerability that ai-rsk misses)
- Code execution vulnerabilities in ai-rsk itself
- Supply chain concerns in ai-rsk's dependencies

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.7.x   | Yes       |
| < 0.7   | No        |
