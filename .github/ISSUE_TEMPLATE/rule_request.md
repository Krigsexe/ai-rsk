---
name: Rule Request
about: Suggest a new detection rule
title: "[RULE] brief description"
labels: enhancement, new-rule
assignees: ''
---

## Vulnerability Pattern

Describe the insecure pattern that LLMs commonly generate.

## CWE Reference

- **CWE ID**: (e.g., CWE-79)
- **Verified on**: [cwe.mitre.org](https://cwe.mitre.org/)

## Vulnerable Code Example

```
paste vulnerable code here
```

## Safe Code Example

```
paste the secure alternative here
```

## Why Existing Tools Miss This

Explain why Semgrep, Gitleaks, or other SAST tools don't catch this pattern.

## Suggested Profile

- [ ] security (always active)
- [ ] gdpr
- [ ] ai-act
- [ ] seo
- [ ] a11y

## Suggested Severity

- [ ] BLOCK (must fix before deploy)
- [ ] WARN (should fix)
- [ ] ADVISE (good practice)
