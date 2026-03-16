# ai-rsk v0.1.1 - Patch Notes

## Bug Fixes

### EVAL_DYNAMIC false positive fix
- **Problem**: Pattern `eval\s*\(` matched the word "retrieval" followed by `(` in comments and prose (e.g., `// Store in sessionStorage for retrieval (no actual generation yet)`)
- **Fix**: Added `\b` word boundary before `eval` on all 3 eval patterns to ensure only standalone `eval(` is matched, not substrings like `retrieval(`
- **Problem**: Generic `exec()` pattern caused false positives on JavaScript methods named `exec` (function declarations, comments, user-defined functions)
- **Fix**: Removed the generic `exec()` pattern from `eval-dynamic.yaml` (JS/TS only). Created a new dedicated rule `EXEC_DYNAMIC_PYTHON` (`exec-dynamic-python.yaml`) targeting only `*.py` files with `^\s*exec\s*\(` anchor to avoid matching method calls like `db.exec()`
- **Fix**: Improved `promisify` pattern to catch `execAsync = ...promisify(child_process.exec)` with variable name suffixes
- **Verified on**: ai-alixia, alixia-gen (geminiService.ts false positive confirmed eliminated), SoS, Majordome, Blinko, Ai-Ops, agentic-workflow, AI-Context-Engineering, Kage, searchly

### Cookie negation per-file fix
- **Problem**: MISSING_HTTPONLY, MISSING_SECURE_COOKIE, MISSING_SAMESITE used project-wide agnostic negation. If ONE file had `httpOnly: true`, the rule was satisfied for ALL files in the project, hiding cookies without flags in other files.
- **Fix**: Added `agnostic_negation` field to Rule struct (default: `true` for backward compatibility). Set to `false` on the 3 cookie rules. When false, negation is checked per-file only.
- **Verified on**: test with 2 files (auth-safe.js with httpOnly + tracking-vulnerable.js without) - only tracking-vulnerable.js triggers, auth-safe.js correctly passes.

### Exclusion improvements
- **Added**: `bundle` directory to EXCLUDED_DIRS in rules.rs, runner.rs, analyze.rs (eliminates false positives on bundled/compiled code like Majordome's `apps/backend/bundle/main.js`)
- **Added**: `*.min.js`, `*.min.css`, `*.min.mjs` file exclusion in `is_excluded()` (eliminates false positives on minified third-party libraries like echarts.min.js, markmap.min.js in Blinko)

## New Rule
- `EXEC_DYNAMIC_PYTHON` (CWE-95, BLOCK) - Detects Python `exec()` and `eval()` with dynamic input, including f-string variants. Targets `*.py` files only.

## Stats
- Rules: 31 -> 32 (1 new Python rule)
- Tests: 162 passing
- Clippy: 0 warnings

## Files Changed
| File | Change |
|---|---|
| `rules/eval-dynamic.yaml` | Removed generic exec pattern, removed Python, added \b word boundary |
| `rules/exec-dynamic-python.yaml` | NEW - Python-only exec/eval detection |
| `rules/missing-httponly.yaml` | Added agnostic_negation: false |
| `rules/missing-secure-cookie.yaml` | Added agnostic_negation: false |
| `rules/missing-samesite.yaml` | Added agnostic_negation: false |
| `src/rules.rs` | Added agnostic_negation field, per-file negation logic, bundle dir, min.js exclusion |
| `src/runner.rs` | Added bundle to SCAN_EXCLUDED_DIRS |
| `src/analyze.rs` | Added bundle to EXCLUDED_DIRS |
| `src/embedded_rules.rs` | Added exec-dynamic-python.yaml include |
| `tests/fixtures/vulnerable/eval.js` | NEW - eval test fixture |
| `tests/fixtures/safe/eval.js` | NEW - safe eval test fixture |

## Validation
Tested on 10 real repositories:
- ai-alixia, SoS, Ai-Ops, Majordome, agentic-workflow, AI-Context-Engineering, Kage, Blinko, alixia-gen, searchly
- Zero false positives on EVAL_DYNAMIC across all 10 repos (1 residual on Blinko: tex-svg-full.js third-party lib, configurable via exclude)
- Cookie per-file negation working correctly on ai-alixia (server-local.ts real positive detected)
