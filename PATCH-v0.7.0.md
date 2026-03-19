# ai-rsk v0.7.0 - Patch Notes - Python Deep Coverage + Tree-sitter AST Filter

## New Rules (12 YAML, category: security)

### Django
| Rule | CWE | Severity | Source |
|---|---|---|---|
| `DJANGO_DEBUG_TRUE` | CWE-489 | BLOCK | Django docs: never deploy with DEBUG=True |
| `DJANGO_SECRET_KEY_HARDCODED` | CWE-798 | BLOCK | Hardcoded SECRET_KEY in source code |
| `DJANGO_ALLOWED_HOSTS_WILDCARD` | CWE-942 | WARN | ALLOWED_HOSTS = ['*'] disables host validation |
| `DJANGO_NO_CSRF_MIDDLEWARE` | CWE-352 | WARN | MIDDLEWARE without CsrfViewMiddleware (negation rule) |

### Flask
| Rule | CWE | Severity | Source |
|---|---|---|---|
| `FLASK_DEBUG_TRUE` | CWE-489 | BLOCK | app.run(debug=True) enables RCE via Werkzeug debugger |

### Python general
| Rule | CWE | Severity | Source |
|---|---|---|---|
| `PYTHON_REQUESTS_NO_TIMEOUT` | CWE-400 | WARN | requests.get/post without timeout (negation rule, per-file) |
| `PYTHON_OS_SYSTEM` | CWE-78 | BLOCK | os.system() / os.popen() command injection |
| `PYTHON_MARSHAL_LOAD` | CWE-502 | BLOCK | marshal.load/loads deserialization RCE |
| `PYTHON_SHELVE_OPEN` | CWE-502 | WARN | shelve.open() uses pickle internally |
| `PYTHON_SQL_FSTRING` | CWE-89 | BLOCK | SQL queries via f-strings (SELECT...FROM, INSERT...INTO, etc.) |
| `PYTHON_JWT_NO_VERIFY` | CWE-347 | BLOCK | jwt.decode() with verify=False or verify_signature=False |
| `PYTHON_EVAL_INPUT` | CWE-95 | BLOCK | eval() with user input (request, input(), data[]) |

## Tree-sitter AST Filter (new architecture)
- New module: `ast_filter.rs` - parses source files via tree-sitter and identifies comments/docstrings
- Regex matches inside comments and Python docstrings are automatically filtered out
- Eliminates false positives on framework documentation (e.g. Flask config.py docstrings)
- Hybrid approach: regex for pattern detection, tree-sitter for context filtering
- String literals in code are NOT filtered (they contain real vulnerability patterns)
- Supported languages: Python (.py), JavaScript (.js/.jsx/.mjs/.cjs), TypeScript (.ts/.tsx)
- Dependencies added: tree-sitter 0.25, tree-sitter-python 0.25, tree-sitter-javascript 0.25

## Bug Fixes
- `runner.rs`: UTF-8 panic in `truncate_output` when slicing multi-byte characters. Fixed with `is_char_boundary` walk-back.
- `detect.rs`: Python ecosystem detection now includes `setup.cfg`, `Pipfile`, and `requirements/` directory.
- `analyze.rs`: `uv.lock` added to Python lockfile detection (uv package manager).
- `python-sql-fstring.yaml`: regex tightened from bare `CREATE` to `CREATE TABLE/INDEX/etc.` to prevent false positives on non-SQL function calls.

## Testing on Real Projects (0 false positives)

| Project | GitHub Stars | Python Lines | Scan Time | New Rules Detected |
|---|---|---|---|---|
| Django framework | 82K | 51,360 | 3m03s | DJANGO_DEBUG_TRUE, DJANGO_SECRET_KEY_HARDCODED, PYTHON_SQL_FSTRING (2), PYTHON_REQUESTS_NO_TIMEOUT |
| djangoproject.com | 3K | ~5,000 | ~30s | DJANGO_DEBUG_TRUE, PYTHON_REQUESTS_NO_TIMEOUT |
| cookiecutter-django | 12K | ~3,000 | ~30s | DJANGO_DEBUG_TRUE, PYTHON_REQUESTS_NO_TIMEOUT |
| Flask (pallets) | 70K | ~10,000 | ~30s | 0 (clean project, docstring FPs eliminated by AST filter) |
| HTTPie CLI | 34K | ~15,000 | ~30s | PYTHON_REQUESTS_NO_TIMEOUT |
| FastAPI | 80K | ~8,000 | ~30s | 0 (clean project) |

## Stats
- Total YAML rules: 67 (55 previous + 12 new Python)
- Python rules: 16 (4 existing + 12 new)
- Total tests: 180 (167 previous + 13 new AST filter tests)
- 0 clippy warnings
- All CWE references verified on cwe.mitre.org
