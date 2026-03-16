# ai-rsk v0.4.0 - Patch Notes — EU AI Act Compliance

## New Rules (4 YAML, category: ai-act)
| Rule | CWE | Severity | Source |
|---|---|---|---|
| `AI_OUTPUT_NO_LABEL` | CWE-451 | WARN | EU AI Act Article 50(1-2) |
| `SYSTEM_PROMPT_CLIENT_EXPOSED` | CWE-200 | BLOCK | EU AI Act + OWASP LLM Top 10:2025 LLM01 |
| `LLM_CALL_NO_AUDIT_LOG` | CWE-778 | WARN | EU AI Act traceability obligations |
| `LLM_NO_TOKEN_LIMIT` | CWE-770 | WARN | EU AI Act + OWASP LLM Top 10:2025 LLM04 |

## Details
- **AI_OUTPUT_NO_LABEL**: Detects LLM API responses sent to users without AI disclosure labeling. Covers OpenAI, Anthropic, Google Generative AI SDKs.
- **SYSTEM_PROMPT_CLIENT_EXPOSED**: Detects system prompts defined in client-accessible code (frontend). Excludes server/api/backend paths. BLOCK severity — system prompt exposure enables prompt injection.
- **LLM_CALL_NO_AUDIT_LOG**: Detects LLM API calls without audit logging. Negation satisfied by observability platforms (Helicone, Langfuse, LangSmith, Portkey, BrainTrust, PromptLayer) or manual audit logging.
- **LLM_NO_TOKEN_LIMIT**: Detects LLM API calls without max_tokens/maxTokens parameter. Prevents cost overrun and DoS.

## SECURITY_RULES.md Liaison
- AI Act section in SECURITY_RULES.md now lists all 4 rule IDs with their severity levels.
- Discipline LLM file includes AI Act section with specific instructions when --ai-act profile is active.

## Enforcement
- August 2, 2026 deadline for EU AI Act transparency obligations.
- Penalties up to 35M EUR or 7% global annual turnover.
