use crate::types::{Ecosystem, Finding, FindingKind, Severity};
use std::collections::HashSet;
use std::path::Path;
use walkdir::WalkDir;

/// Directories to skip when scanning for source files.
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    ".git",
    "dist",
    "build",
    "bundle",
    "out",
    "__pycache__",
    ".pytest_cache",
    "target",
    ".venv",
    "venv",
    "env",
    ".next",
    ".nuxt",
];

/// Run project analysis (couche 3) and return ADVISE findings.
/// This analyzes the project structure, not the code itself.
/// Every finding is based on file presence/absence - no guessing.
/// `active_profiles` controls which compliance checks run (e.g., "gdpr" enables cookie/privacy checks).
pub fn analyze_project(
    project_path: &Path,
    ecosystems: &[Ecosystem],
    active_profiles: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Tests detection
    findings.extend(check_tests(project_path, ecosystems));

    // 2. CI/CD detection
    findings.extend(check_ci_cd(project_path));

    // 3. Dead dependencies (JS only for now - factual, verified)
    // If knip is available, it handles dead code/deps detection (runner.rs runs it).
    // Our fallback detection only runs when knip is NOT installed.
    if ecosystems.contains(&Ecosystem::JavaScript) && !crate::runner::knip_available(project_path) {
        findings.extend(check_dead_deps_js(project_path));
    }

    // 4. Documentation presence
    findings.extend(check_documentation(project_path));

    // 5. Framework detection + advice
    if ecosystems.contains(&Ecosystem::JavaScript) {
        findings.extend(analyze_js_stack(project_path));
    }

    // 6. Console.log strip mechanism (JS only)
    if ecosystems.contains(&Ecosystem::JavaScript) {
        findings.extend(check_console_strip(project_path));
    }

    // 7. Tamper protection - detect if ai-rsk has been bypassed
    findings.extend(check_tamper_protection(project_path, ecosystems));

    // 8. GDPR checks (only when gdpr profile is active)
    if active_profiles.iter().any(|p| p == "gdpr") {
        findings.extend(check_cookie_banner(project_path));
        findings.extend(check_privacy_page(project_path));
    }

    // 9. SEO checks (only when seo profile is active)
    if active_profiles.iter().any(|p| p == "seo") {
        findings.extend(check_robots_txt(project_path));
        findings.extend(check_sitemap(project_path));
        findings.extend(check_meta_viewport(project_path));
        findings.extend(check_canonical(project_path));
    }

    // 10. Infrastructure checks (always active)
    findings.extend(check_lockfile(project_path, ecosystems));
    findings.extend(check_env_gitignored(project_path));
    findings.extend(check_dockerfile_root(project_path));

    findings
}

/// Check if the project has any test files or test framework configured.
fn check_tests(project_path: &Path, ecosystems: &[Ecosystem]) -> Vec<Finding> {
    let mut has_test_files = false;
    let mut has_test_config = false;

    // Check for test configuration files
    let test_configs = [
        "jest.config.js",
        "jest.config.ts",
        "jest.config.mjs",
        "jest.config.cjs",
        "vitest.config.js",
        "vitest.config.ts",
        "vitest.config.mjs",
        "pytest.ini",
        "pyproject.toml", // may contain [tool.pytest]
        "setup.cfg",      // may contain [tool:pytest]
        "tox.ini",
        ".mocharc.yml",
        ".mocharc.json",
        "karma.conf.js",
        "ava.config.js",
        "ava.config.mjs",
    ];

    for config in &test_configs {
        if project_path.join(config).exists() {
            has_test_config = true;
            break;
        }
    }

    // Check for test directories
    let test_dirs = ["tests", "test", "__tests__", "spec", "specs"];
    for dir in &test_dirs {
        let test_dir = project_path.join(dir);
        if test_dir.is_dir() {
            // Verify the directory actually contains files
            if std::fs::read_dir(&test_dir)
                .ok()
                .is_some_and(|entries| entries.count() > 0)
            {
                has_test_files = true;
                break;
            }
        }
    }

    // Check for test files in src/ (*.test.*, *.spec.*)
    if !has_test_files {
        for entry in WalkDir::new(project_path)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if is_excluded_dir(path) {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (name.contains(".test.") || name.contains(".spec.") || name.contains("_test."))
            {
                has_test_files = true;
                break;
            }
        }
    }

    // Rust projects: check for #[cfg(test)] in any .rs file
    if !has_test_files && ecosystems.contains(&Ecosystem::Rust) {
        for entry in WalkDir::new(project_path)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file() && e.path().extension().is_some_and(|ext| ext == "rs")
            })
        {
            if is_excluded_dir(entry.path()) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(entry.path())
                && (content.contains("#[cfg(test)]") || content.contains("#[test]"))
            {
                has_test_files = true;
                break;
            }
        }
    }

    // Python: check for test_*.py files
    if !has_test_files && ecosystems.contains(&Ecosystem::Python) {
        for entry in WalkDir::new(project_path)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if is_excluded_dir(entry.path()) {
                continue;
            }
            if let Some(name) = entry.path().file_name().and_then(|n| n.to_str())
                && name.starts_with("test_")
                && name.ends_with(".py")
            {
                has_test_files = true;
                break;
            }
        }
    }

    // Go: check for *_test.go files
    if !has_test_files && ecosystems.contains(&Ecosystem::Go) {
        for entry in WalkDir::new(project_path)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if is_excluded_dir(entry.path()) {
                continue;
            }
            if let Some(name) = entry.path().file_name().and_then(|n| n.to_str())
                && name.ends_with("_test.go")
            {
                has_test_files = true;
                break;
            }
        }
    }

    if !has_test_files && !has_test_config {
        return vec![Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: "NO_TESTS".to_string(),
                question: "No test framework or test files detected. The LLM MUST ask the developer: \"Do you want me to set up a test framework?\"".to_string(),
            },
            file: None,
            line: None,
            message: "No test framework or test files detected in the project.".to_string(),
        }];
    }

    vec![]
}

/// Check if CI/CD is configured.
fn check_ci_cd(project_path: &Path) -> Vec<Finding> {
    let ci_indicators = [
        ".github/workflows",
        ".gitlab-ci.yml",
        ".circleci",
        "Jenkinsfile",
        ".travis.yml",
        "bitbucket-pipelines.yml",
        "azure-pipelines.yml",
        ".drone.yml",
        ".woodpecker.yml",
        ".forgejo/workflows",
        ".gitea/workflows",
    ];

    for indicator in &ci_indicators {
        let ci_path = project_path.join(indicator);
        if ci_path.exists() {
            // For directories (like .github/workflows), check they contain files
            if ci_path.is_dir() {
                if std::fs::read_dir(&ci_path)
                    .ok()
                    .is_some_and(|entries| entries.count() > 0)
                {
                    return vec![];
                }
            } else {
                return vec![];
            }
        }
    }

    vec![Finding {
        severity: Severity::Advise,
        kind: FindingKind::ProjectAdvice {
            advice_id: "NO_CI_CD".to_string(),
            question: "No CI/CD pipeline detected. Without CI/CD, ai-rsk security gates can be bypassed locally (--no-verify, || true). The LLM MUST ask the developer: \"Do you want me to create a CI/CD pipeline with ai-rsk scan integrated?\"".to_string(),
        },
        file: None,
        line: None,
        message: "No CI/CD pipeline detected - ai-rsk scan can be bypassed locally without CI as last defense.".to_string(),
    }]
}

/// Check for dead dependencies in a JavaScript/TypeScript project.
/// Dead = listed in package.json dependencies but never imported in source files.
fn check_dead_deps_js(project_path: &Path) -> Vec<Finding> {
    let pkg_path = project_path.join("package.json");
    let pkg_content = match std::fs::read_to_string(&pkg_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    // Parse package.json to extract dependency names.
    // We use a minimal JSON parser approach - no need for serde_json as a dep.
    // Extract keys from "dependencies" and "devDependencies" objects.
    let deps = extract_dependency_names(&pkg_content);
    if deps.is_empty() {
        return vec![];
    }

    // Collect all import/require references from source files
    let mut used_deps: HashSet<String> = HashSet::new();

    for entry in WalkDir::new(project_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if is_excluded_dir(path) {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(
            ext,
            "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" | "mts" | "cts"
        ) {
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check each dep against imports in this file
        for dep in &deps {
            if used_deps.contains(dep) {
                continue; // Already found
            }

            // Match: require('dep'), require("dep"), from 'dep', from "dep"
            // Also match: require('dep/...'), from 'dep/...'
            // Also match: import 'dep' (side-effect import)
            if content.contains(&format!("'{dep}'"))
                || content.contains(&format!("\"{dep}\""))
                || content.contains(&format!("'{dep}/"))
                || content.contains(&format!("\"{dep}/"))
            {
                used_deps.insert(dep.clone());
            }
        }
    }

    // Also check package.json scripts for dependency usage (e.g., "concurrently" in npm scripts).
    // Only look inside the "scripts" section to avoid false matches against dependency keys.
    if let Ok(pkg_full) = std::fs::read_to_string(project_path.join("package.json"))
        && let Some(scripts_start) = pkg_full.find("\"scripts\"")
    {
        let after_key = &pkg_full[scripts_start..];
        if let Some(brace_pos) = after_key.find('{') {
            let obj = &after_key[brace_pos..];
            let mut depth = 0;
            let mut end = obj.len();
            for (i, ch) in obj.char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let scripts_section = &obj[..end];
            for dep in &deps {
                if scripts_section.contains(dep.as_str()) {
                    used_deps.insert(dep.clone());
                }
            }
        }
    }

    // Find deps that are never imported
    let dead: Vec<String> = deps
        .into_iter()
        .filter(|d| !used_deps.contains(d))
        .collect();

    if dead.is_empty() {
        return vec![];
    }

    let dead_list = dead
        .iter()
        .map(|d| format!("  - {d}"))
        .collect::<Vec<_>>()
        .join("\n");

    vec![Finding {
        severity: Severity::Advise,
        kind: FindingKind::ProjectAdvice {
            advice_id: "DEAD_DEPENDENCIES".to_string(),
            question: format!(
                "{} dependencies in package.json are never imported in source files:\n{}\nThe LLM MUST remove these or ask the developer why they are present.",
                dead.len(),
                dead_list
            ),
        },
        file: Some(std::path::PathBuf::from("package.json")),
        line: None,
        message: format!(
            "{} unused dependencies detected in package.json.",
            dead.len()
        ),
    }]
}

/// Extract dependency names from package.json content.
/// Minimal parser - extracts keys from "dependencies" and "devDependencies".
fn extract_dependency_names(json_content: &str) -> Vec<String> {
    let mut deps = Vec::new();

    for section in ["\"dependencies\"", "\"devDependencies\""] {
        if let Some(section_start) = json_content.find(section) {
            // Find the opening brace of the object
            let after_key = &json_content[section_start + section.len()..];
            if let Some(brace_start) = after_key.find('{') {
                let obj_content = &after_key[brace_start + 1..];
                // Find the matching closing brace
                let mut depth = 1;
                let mut end = 0;
                for (i, ch) in obj_content.char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let obj_str = &obj_content[..end];
                // Extract keys (quoted strings before ':')
                let mut in_string = false;
                let mut key_start = None;
                let chars = obj_str.char_indices().peekable();
                for (i, ch) in chars {
                    match ch {
                        '"' if !in_string => {
                            in_string = true;
                            key_start = Some(i + 1);
                        }
                        '"' if in_string => {
                            in_string = false;
                            if let Some(start) = key_start {
                                let key = &obj_str[start..i];
                                // Check if next non-whitespace is ':'
                                let rest = obj_str[i + 1..].trim_start();
                                if rest.starts_with(':') {
                                    // Skip @types/* and @scope/name type definitions
                                    if !key.starts_with("@types/") {
                                        deps.push(key.to_string());
                                    }
                                }
                            }
                            key_start = None;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    deps
}

/// Check for documentation files.
fn check_documentation(project_path: &Path) -> Vec<Finding> {
    let has_readme = project_path.join("README.md").exists()
        || project_path.join("readme.md").exists()
        || project_path.join("README").exists()
        || project_path.join("README.txt").exists()
        || project_path.join("README.rst").exists();

    if !has_readme {
        return vec![Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: "NO_README".to_string(),
                question: "No README file detected. The LLM MUST ask the developer: \"Do you want me to create a README.md for this project?\"".to_string(),
            },
            file: None,
            line: None,
            message: "No README file found in the project root.".to_string(),
        }];
    }

    vec![]
}

/// Analyze JavaScript/TypeScript stack for common issues.
fn analyze_js_stack(project_path: &Path) -> Vec<Finding> {
    let pkg_path = project_path.join("package.json");
    let pkg_content = match std::fs::read_to_string(&pkg_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();

    // Detect duplicate HTTP client libraries
    let http_clients: Vec<&str> = [
        "axios",
        "node-fetch",
        "got",
        "superagent",
        "request",
        "undici",
    ]
    .iter()
    .filter(|dep| pkg_content.contains(&format!("\"{}\"", dep)))
    .copied()
    .collect();

    if http_clients.len() > 1 {
        findings.push(Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: "DUPLICATE_HTTP_CLIENTS".to_string(),
                question: format!(
                    "Multiple HTTP client libraries detected: {}. These all serve the same purpose. The LLM MUST ask the developer: \"You have {} HTTP client libraries. Which one should we standardize on?\"",
                    http_clients.join(", "),
                    http_clients.len()
                ),
            },
            file: Some(std::path::PathBuf::from("package.json")),
            line: None,
            message: format!(
                "Duplicate HTTP client libraries: {}.",
                http_clients.join(", ")
            ),
        });
    }

    // Detect deprecated packages
    let deprecated_deps: Vec<(&str, &str)> = [
        (
            "request",
            "DEPRECATED since Feb 2020 - use fetch(), axios, or got",
        ),
        (
            "moment",
            "In maintenance mode since Sep 2020 - consider dayjs, date-fns, or Intl API",
        ),
    ]
    .into_iter()
    .filter(|(dep, _)| {
        // Check it's actually a dependency key, not just mentioned anywhere
        pkg_content.contains(&format!("\"{dep}\""))
    })
    .collect();

    for (dep, reason) in &deprecated_deps {
        findings.push(Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: format!("DEPRECATED_DEP_{}", dep.to_uppercase()),
                question: format!(
                    "Dependency '{}' is deprecated/unmaintained: {}. The LLM MUST ask the developer: \"Do you want me to migrate away from {}?\"",
                    dep, reason, dep
                ),
            },
            file: Some(std::path::PathBuf::from("package.json")),
            line: None,
            message: format!("Deprecated dependency: {} - {}", dep, reason),
        });
    }

    findings
}

/// Check if a path is inside an excluded directory.
fn is_excluded_dir(path: &Path) -> bool {
    path.components().any(|c| {
        if let std::path::Component::Normal(name) = c
            && let Some(name_str) = name.to_str()
        {
            return EXCLUDED_DIRS.contains(&name_str);
        }
        false
    })
}

/// Check if a JavaScript project has a mechanism to strip console.log in production.
/// This is NO_CONSOLE_STRIP from the spec - detects ABSENCE of any of:
/// - ESLint "no-console" rule
/// - Terser/esbuild/vite drop_console/pure_funcs config
/// - A structured logger (winston, pino, bunyan) replacing console.log
fn check_console_strip(project_path: &Path) -> Vec<Finding> {
    // Check ESLint configs for "no-console"
    let eslint_configs = [
        "eslint.config.js",
        "eslint.config.mjs",
        "eslint.config.cjs",
        "eslint.config.ts",
        ".eslintrc",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.json",
        ".eslintrc.yml",
        ".eslintrc.yaml",
    ];

    for config in &eslint_configs {
        let config_path = project_path.join(config);
        if let Ok(content) = std::fs::read_to_string(&config_path)
            && content.contains("no-console")
        {
            return vec![];
        }
    }

    // Check package.json for eslintConfig with no-console
    let pkg_path = project_path.join("package.json");
    if let Ok(pkg_content) = std::fs::read_to_string(&pkg_path) {
        if pkg_content.contains("no-console") {
            return vec![];
        }

        // Check for structured loggers in dependencies (replace console.log)
        let loggers = ["winston", "pino", "bunyan", "log4js", "signale"];
        for logger in &loggers {
            if pkg_content.contains(&format!("\"{logger}\"")) {
                return vec![];
            }
        }
    }

    // Check build configs for drop_console / pure_funcs
    // Note: esbuild uses "drop:" (no underscore), not "drop_console"
    let build_configs = [
        ("vite.config.js", "drop_console"),
        ("vite.config.ts", "drop_console"),
        ("vite.config.mjs", "drop_console"),
        ("vite.config.mts", "drop_console"),
        ("webpack.config.js", "drop_console"),
        ("webpack.config.ts", "drop_console"),
        ("next.config.js", "drop_console"),
        ("next.config.mjs", "drop_console"),
        ("next.config.ts", "drop_console"),
        ("esbuild.config.js", "drop"),
        ("esbuild.config.mjs", "drop"),
        ("rollup.config.js", "pure_funcs"),
        ("rollup.config.mjs", "pure_funcs"),
        // Also check for terser config patterns
        ("vite.config.js", "pure_funcs"),
        ("vite.config.ts", "pure_funcs"),
        ("webpack.config.js", "pure_funcs"),
        // esbuild uses "drop:" in Vite config (e.g., drop: ['console'])
        ("vite.config.js", "\"drop\""),
        ("vite.config.ts", "\"drop\""),
        ("vite.config.mjs", "\"drop\""),
        ("vite.config.mts", "\"drop\""),
        ("vite.config.js", "drop:"),
        ("vite.config.ts", "drop:"),
        ("vite.config.mjs", "drop:"),
        ("vite.config.mts", "drop:"),
    ];

    // Check root directory
    for (config_file, pattern) in &build_configs {
        let config_path = project_path.join(config_file);
        if let Ok(content) = std::fs::read_to_string(&config_path)
            && content.contains(pattern)
        {
            return vec![];
        }
    }

    // Also check common subdirectories (monorepos with frontend/ client/ etc.)
    let subdirs = ["frontend", "client", "app", "src"];
    for subdir in &subdirs {
        for (config_file, pattern) in &build_configs {
            let config_path = project_path.join(subdir).join(config_file);
            if let Ok(content) = std::fs::read_to_string(&config_path)
                && content.contains(pattern)
            {
                return vec![];
            }
        }
    }

    // No mechanism found - this is a WARN (not BLOCK, because some projects
    // may use other mechanisms we don't detect)
    vec![Finding {
        severity: Severity::Warn,
        kind: FindingKind::ProjectAdvice {
            advice_id: "NO_CONSOLE_STRIP".to_string(),
            question: "No mechanism to strip console.log in production detected. Options:\n  1. ESLint 'no-console' rule (eslint.config.js)\n  2. Build tool: terser drop_console, esbuild drop\n  3. Structured logger (winston, pino) replacing console.log\nThe LLM MUST ask the developer: \"How do you handle console.log in production?\"".to_string(),
        },
        file: None,
        line: None,
        message: "No console.log stripping mechanism detected - console.log statements will leak to production, potentially exposing sensitive data.".to_string(),
    }]
}

/// Detect if ai-rsk has been tampered with or bypassed.
/// Checks for common LLM bypass patterns in package.json and CI configs.
fn check_tamper_protection(project_path: &Path, ecosystems: &[Ecosystem]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check package.json for bypass patterns (JS/TS ecosystem)
    if ecosystems.contains(&Ecosystem::JavaScript) {
        let pkg_path = project_path.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            // Detect || true, || exit 0, or stdout redirection after ai-rsk
            let bypass_patterns = [
                "ai-rsk scan || true",
                "ai-rsk scan --strict || true",
                "ai-rsk scan --full || true",
                "ai-rsk scan || exit 0",
                "ai-rsk scan > /dev/null",
                "ai-rsk scan 2>/dev/null",
                "ai-rsk scan &>/dev/null",
            ];

            for pattern in &bypass_patterns {
                if content.contains(pattern) {
                    findings.push(Finding {
                        severity: Severity::Block,
                        kind: FindingKind::ProjectAdvice {
                            advice_id: "AIRSK_BYPASSED".to_string(),
                            question: format!(
                                "ai-rsk security gate has been BYPASSED in package.json with '{}'. This defeats the entire purpose of the security gate. The developer MUST be notified - this change was likely made by the LLM to avoid fixing security issues.",
                                pattern
                            ),
                        },
                        file: Some(std::path::PathBuf::from("package.json")),
                        line: None,
                        message: format!("SECURITY BYPASS DETECTED: ai-rsk scan neutralized with '{}'.", pattern),
                    });
                    break;
                }
            }

            // Detect if ai-rsk was removed from prebuild entirely
            if content.contains("\"scripts\"") && !content.contains("ai-rsk") {
                // Only warn if we previously installed (check for SECURITY_RULES.md presence)
                if project_path.join("SECURITY_RULES.md").exists() {
                    findings.push(Finding {
                        severity: Severity::Warn,
                        kind: FindingKind::ProjectAdvice {
                            advice_id: "AIRSK_REMOVED_FROM_PREBUILD".to_string(),
                            question: "ai-rsk was previously installed (SECURITY_RULES.md exists) but is no longer in package.json scripts. This may indicate the LLM removed it to avoid fixing security issues.".to_string(),
                        },
                        file: Some(std::path::PathBuf::from("package.json")),
                        line: None,
                        message: "ai-rsk is not in package.json scripts but SECURITY_RULES.md exists - was it removed?".to_string(),
                    });
                }
            }
        }
    }

    // Check for --no-verify in git hooks or CI
    let ci_files = [".github/workflows", ".gitlab-ci.yml"];

    for ci_file in &ci_files {
        let ci_path = project_path.join(ci_file);
        if ci_path.is_dir() {
            // Scan workflow files
            for entry in WalkDir::new(&ci_path)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if content.contains("--no-verify") {
                        findings.push(Finding {
                            severity: Severity::Warn,
                            kind: FindingKind::ProjectAdvice {
                                advice_id: "CI_NO_VERIFY".to_string(),
                                question: "--no-verify found in CI configuration. This skips git hooks including ai-rsk security checks.".to_string(),
                            },
                            file: Some(entry.path().strip_prefix(project_path).unwrap_or(entry.path()).to_path_buf()),
                            line: None,
                            message: "--no-verify in CI configuration bypasses security hooks.".to_string(),
                        });
                    }
                }
            }
        } else if ci_path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&ci_path) {
                if content.contains("--no-verify") {
                    findings.push(Finding {
                        severity: Severity::Warn,
                        kind: FindingKind::ProjectAdvice {
                            advice_id: "CI_NO_VERIFY".to_string(),
                            question: "--no-verify found in CI configuration. This skips git hooks including ai-rsk security checks.".to_string(),
                        },
                        file: Some(std::path::PathBuf::from(ci_file)),
                        line: None,
                        message: "--no-verify in CI configuration bypasses security hooks.".to_string(),
                    });
                }
            }
        }
    }

    findings
}

/// Infra: Check if the project has a lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, etc.).
/// Without a lockfile, dependency versions are non-deterministic across environments.
fn check_lockfile(project_path: &Path, ecosystems: &[Ecosystem]) -> Vec<Finding> {
    let lockfiles: Vec<(&str, &[Ecosystem])> = vec![
        ("package-lock.json", &[Ecosystem::JavaScript]),
        ("yarn.lock", &[Ecosystem::JavaScript]),
        ("pnpm-lock.yaml", &[Ecosystem::JavaScript]),
        ("bun.lockb", &[Ecosystem::JavaScript]),
        ("Cargo.lock", &[Ecosystem::Rust]),
        ("go.sum", &[Ecosystem::Go]),
        ("poetry.lock", &[Ecosystem::Python]),
        ("Pipfile.lock", &[Ecosystem::Python]),
        ("requirements.txt", &[Ecosystem::Python]),
    ];

    for (lockfile, applicable_ecosystems) in &lockfiles {
        if applicable_ecosystems.iter().any(|e| ecosystems.contains(e))
            && project_path.join(lockfile).exists()
        {
            return vec![];
        }
    }

    // Only warn if an ecosystem that uses lockfiles is detected
    let needs_lockfile = ecosystems.iter().any(|e| {
        matches!(
            e,
            Ecosystem::JavaScript | Ecosystem::Rust | Ecosystem::Go | Ecosystem::Python
        )
    });

    if !needs_lockfile {
        return vec![];
    }

    vec![Finding {
        severity: Severity::Warn,
        kind: FindingKind::ProjectAdvice {
            advice_id: "NO_LOCKFILE".to_string(),
            question: "No dependency lockfile found. Without a lockfile, dependency versions are non-deterministic — different environments may install different versions, leading to \"works on my machine\" bugs and potential supply chain attacks. Run your package manager's install command to generate one.".to_string(),
        },
        file: None,
        line: None,
        message: "No dependency lockfile found — builds are non-deterministic.".to_string(),
    }]
}

/// Infra: Check if .env is in .gitignore.
/// .env files contain secrets (API keys, DB passwords) and must never be committed.
fn check_env_gitignored(project_path: &Path) -> Vec<Finding> {
    // Only check if .env exists
    if !project_path.join(".env").exists() {
        return vec![];
    }

    let gitignore_path = project_path.join(".gitignore");
    if let Ok(content) = std::fs::read_to_string(&gitignore_path) {
        if content.lines().any(|line| {
            let trimmed = line.trim();
            trimmed == ".env" || trimmed == ".env*" || trimmed == ".env.*" || trimmed == "*.env"
        }) {
            return vec![];
        }
    }

    vec![Finding {
        severity: Severity::Block,
        kind: FindingKind::ProjectAdvice {
            advice_id: "ENV_NOT_GITIGNORED".to_string(),
            question: ".env file exists but is NOT listed in .gitignore. This means secrets (API keys, database passwords, tokens) will be committed to git history. Add .env to .gitignore IMMEDIATELY.".to_string(),
        },
        file: Some(std::path::PathBuf::from(".env")),
        line: None,
        message: ".env file exists but is not in .gitignore — secrets will be committed to git.".to_string(),
    }]
}

/// Infra: Check if Dockerfile runs as root (no USER directive).
/// Running containers as root is a security risk — if the container is compromised,
/// the attacker has root access to the host kernel's attack surface.
fn check_dockerfile_root(project_path: &Path) -> Vec<Finding> {
    let dockerfile_names = ["Dockerfile", "dockerfile", "Containerfile"];

    for name in &dockerfile_names {
        let path = project_path.join(name);
        if let Ok(content) = std::fs::read_to_string(&path) {
            // Check if USER directive exists (case-insensitive line start)
            let has_user = content.lines().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("USER ") || trimmed.starts_with("user ")
            });

            if !has_user {
                return vec![Finding {
                    severity: Severity::Warn,
                    kind: FindingKind::ProjectAdvice {
                        advice_id: "DOCKERFILE_ROOT_USER".to_string(),
                        question: format!(
                            "{} has no USER directive — the container runs as root. If compromised, an attacker has root-level access. Add a non-root user: USER 1001 or USER appuser.",
                            name
                        ),
                    },
                    file: Some(std::path::PathBuf::from(name)),
                    line: None,
                    message: format!("{} runs as root — no USER directive found.", name),
                }];
            }
        }
    }

    vec![]
}

/// SEO: Check if the project has a robots.txt file.
/// robots.txt tells search engines which pages to crawl and which to skip.
fn check_robots_txt(project_path: &Path) -> Vec<Finding> {
    // Check common locations
    let locations = ["robots.txt", "public/robots.txt", "static/robots.txt"];
    for loc in &locations {
        if project_path.join(loc).exists() {
            // Also check if robots.txt exposes sensitive paths
            if let Ok(content) = std::fs::read_to_string(project_path.join(loc)) {
                let content_lower = content.to_lowercase();
                let sensitive_patterns = [
                    "/admin",
                    "/api/",
                    "/dashboard",
                    "/internal",
                    "/staging",
                    "/debug",
                    "/phpMyAdmin",
                    "/wp-admin",
                ];
                for pattern in &sensitive_patterns {
                    if content_lower.contains(&format!("disallow: {}", pattern.to_lowercase())) {
                        return vec![Finding {
                            severity: Severity::Warn,
                            kind: FindingKind::ProjectAdvice {
                                advice_id: "ROBOTS_EXPOSES_SENSITIVE".to_string(),
                                question: format!(
                                    "robots.txt contains Disallow for '{}'. While this prevents crawling, it REVEALS the existence of sensitive paths to anyone reading robots.txt. Use authentication and access controls instead of relying on robots.txt for security.",
                                    pattern
                                ),
                            },
                            file: Some(std::path::PathBuf::from(loc)),
                            line: None,
                            message: format!("robots.txt reveals sensitive path: {}", pattern),
                        }];
                    }
                }
            }
            return vec![];
        }
    }

    vec![Finding {
        severity: Severity::Advise,
        kind: FindingKind::ProjectAdvice {
            advice_id: "NO_ROBOTS_TXT".to_string(),
            question: "No robots.txt file found. Search engines need robots.txt to know which pages to crawl. The LLM MUST ask: \"Do you want me to create a robots.txt?\"".to_string(),
        },
        file: None,
        line: None,
        message: "No robots.txt file found at the project root.".to_string(),
    }]
}

/// SEO: Check if the project has a sitemap.xml file.
fn check_sitemap(project_path: &Path) -> Vec<Finding> {
    let locations = [
        "sitemap.xml",
        "public/sitemap.xml",
        "static/sitemap.xml",
        "sitemap.xml.gz",
        "public/sitemap.xml.gz",
    ];
    for loc in &locations {
        if project_path.join(loc).exists() {
            return vec![];
        }
    }

    // Also check if robots.txt references a sitemap
    let robots_locations = ["robots.txt", "public/robots.txt", "static/robots.txt"];
    for loc in &robots_locations {
        if let Ok(content) = std::fs::read_to_string(project_path.join(loc)) {
            if content.to_lowercase().contains("sitemap:") {
                return vec![];
            }
        }
    }

    vec![Finding {
        severity: Severity::Advise,
        kind: FindingKind::ProjectAdvice {
            advice_id: "NO_SITEMAP".to_string(),
            question: "No sitemap.xml found. A sitemap helps search engines discover all pages on your site. The LLM MUST ask: \"Do you want me to create a sitemap.xml?\"".to_string(),
        },
        file: None,
        line: None,
        message: "No sitemap.xml found at the project root.".to_string(),
    }]
}

/// SEO: Check if HTML files have a meta viewport tag for mobile rendering.
fn check_meta_viewport(project_path: &Path) -> Vec<Finding> {
    let html_extensions = ["html", "htm"];
    let mut has_html = false;
    let mut has_viewport = false;

    for entry in WalkDir::new(project_path)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded_dir(e.path()))
    {
        let ext = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !html_extensions.contains(&ext) {
            continue;
        }
        has_html = true;

        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            if content.to_lowercase().contains("viewport") {
                has_viewport = true;
                break;
            }
        }
    }

    if has_html && !has_viewport {
        vec![Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: "NO_META_VIEWPORT".to_string(),
                question: "HTML files found but no meta viewport tag detected. Without it, mobile devices render the page at desktop width. Add: <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">".to_string(),
            },
            file: None,
            line: None,
            message: "No meta viewport tag found in HTML files — mobile rendering will be broken.".to_string(),
        }]
    } else {
        vec![]
    }
}

/// SEO: Check if HTML files have canonical URLs to prevent duplicate content.
fn check_canonical(project_path: &Path) -> Vec<Finding> {
    let html_extensions = ["html", "htm"];
    let mut has_html = false;
    let mut has_canonical = false;

    for entry in WalkDir::new(project_path)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded_dir(e.path()))
    {
        let ext = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !html_extensions.contains(&ext) {
            continue;
        }
        has_html = true;

        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            let lower = content.to_lowercase();
            if lower.contains("rel=\"canonical\"") || lower.contains("rel='canonical'") {
                has_canonical = true;
                break;
            }
        }
    }

    if has_html && !has_canonical {
        vec![Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: "NO_CANONICAL".to_string(),
                question: "HTML files found but no canonical URL tag detected. Without canonical tags, search engines may index duplicate content. Add: <link rel=\"canonical\" href=\"https://yoursite.com/page\">".to_string(),
            },
            file: None,
            line: None,
            message: "No canonical URL tags found in HTML files — risk of duplicate content in search results.".to_string(),
        }]
    } else {
        vec![]
    }
}

/// GDPR: Check if the project has a privacy policy page.
/// Looks for files or routes named privacy, privacy-policy, politique-de-confidentialite, etc.
/// Also checks for links to a privacy page in HTML/JSX files.
/// Severity: ADVISE — the project should have a privacy page if it collects any user data.
fn check_privacy_page(project_path: &Path) -> Vec<Finding> {
    // Check for privacy page files (static sites, Next.js pages, etc.)
    let privacy_file_patterns = [
        // English
        "privacy",
        "privacy-policy",
        "privacy_policy",
        "privacypolicy",
        // French
        "politique-de-confidentialite",
        "politique_confidentialite",
        "confidentialite",
        // German
        "datenschutz",
        // Spanish
        "politica-de-privacidad",
        // Legal catch-all
        "legal",
        "mentions-legales",
        "mentions_legales",
    ];

    let source_extensions = [
        "html", "htm", "jsx", "tsx", "js", "ts", "vue", "svelte", "md", "mdx",
    ];

    for entry in WalkDir::new(project_path)
        .max_depth(6)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded_dir(e.path()))
    {
        let file_name = entry
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check if filename matches a privacy page pattern
        for pattern in &privacy_file_patterns {
            if file_name == *pattern {
                return vec![];
            }
        }
    }

    // Check for links to privacy pages in source files
    let link_patterns = [
        "/privacy",
        "/privacy-policy",
        "/politique-de-confidentialite",
        "/confidentialite",
        "/datenschutz",
        "/legal",
        "/mentions-legales",
        "privacy.html",
        "privacy-policy.html",
    ];

    for entry in WalkDir::new(project_path)
        .max_depth(6)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded_dir(e.path()))
    {
        let ext = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !source_extensions.contains(&ext) {
            continue;
        }

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let content_lower = content.to_lowercase();
        for pattern in &link_patterns {
            if content_lower.contains(pattern) {
                return vec![];
            }
        }
    }

    vec![Finding {
        severity: Severity::Advise,
        kind: FindingKind::ProjectAdvice {
            advice_id: "NO_PRIVACY_PAGE".to_string(),
            question: "No privacy policy page detected in the project. Under RGPD/GDPR Article 13, you MUST inform users about data collection, processing purposes, data retention, and their rights (access, rectification, erasure). The LLM MUST ask the developer: \"Do you want me to create a privacy policy page? I'll need to know: what data you collect, why, how long you keep it, and who has access.\"".to_string(),
        },
        file: None,
        line: None,
        message: "No privacy policy page found. RGPD/GDPR Article 13 requires informing users about data processing.".to_string(),
    }]
}

/// GDPR: Check if the project has tracking scripts but no cookie consent banner/CMP.
/// This is a project-level check: if ANY tracking is detected in the codebase,
/// there MUST be a consent management mechanism present somewhere.
/// Severity: WARN (the tracking scripts themselves are caught by TRACKING_NO_CONSENT rule as BLOCK).
fn check_cookie_banner(project_path: &Path) -> Vec<Finding> {
    let tracking_patterns = [
        "gtag(",
        "googletagmanager.com",
        "GoogleAnalyticsObject",
        "fbq(",
        "_paq.push",
        "hotjar.com",
    ];

    let cmp_patterns = [
        // CMP libraries and services
        "cookiebot",
        "CookieBot",
        "onetrust",
        "OneTrust",
        "cookieyes",
        "CookieYes",
        "cookie-script",
        "cookie_script",
        "tarteaucitron",
        "klaro",
        "Klaro",
        "osano",
        "Osano",
        "didomi",
        "Didomi",
        "axeptio",
        "Axeptio",
        "secureprivacy",
        // Custom cookie banner components/patterns
        "cookie-banner",
        "cookie-consent",
        "cookieBanner",
        "cookieConsent",
        "CookieBanner",
        "CookieConsent",
        "gdpr-banner",
        "gdprBanner",
        "consent-banner",
        "consentBanner",
        "ConsentBanner",
        // Google Consent Mode
        "consent', 'default",
        "consent\", \"default",
    ];

    let mut has_tracking = false;
    let mut has_cmp = false;

    let extensions = [
        "html", "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte",
    ];

    for entry in WalkDir::new(project_path)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded_dir(e.path()))
    {
        let ext = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if !extensions.contains(&ext) {
            continue;
        }

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if !has_tracking {
            for pattern in &tracking_patterns {
                if content.contains(pattern) {
                    has_tracking = true;
                    break;
                }
            }
        }

        if !has_cmp {
            for pattern in &cmp_patterns {
                if content.contains(pattern) {
                    has_cmp = true;
                    break;
                }
            }
        }

        // Early exit if both found
        if has_tracking && has_cmp {
            return vec![];
        }
    }

    // Also check package.json for CMP dependencies
    if !has_cmp {
        let pkg_path = project_path.join("package.json");
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            let cmp_deps = [
                "react-cookie-consent",
                "cookie-consent",
                "vue-cookie-comply",
                "@cookiebot",
                "onetrust",
                "tarteaucitron",
                "klaro",
                "osano",
                "didomi",
            ];
            for dep in &cmp_deps {
                if content.contains(dep) {
                    has_cmp = true;
                    break;
                }
            }
        }
    }

    if has_tracking && !has_cmp {
        vec![Finding {
            severity: Severity::Warn,
            kind: FindingKind::ProjectAdvice {
                advice_id: "NO_COOKIE_BANNER".to_string(),
                question: "Tracking scripts detected (gtag, Facebook Pixel, Matomo, or Hotjar) but no Cookie Consent Management Platform (CMP) found. Under RGPD/GDPR and ePrivacy Directive, a cookie consent banner is REQUIRED before any non-essential cookies are set. The LLM MUST ask the developer: \"Which CMP do you want to use? Options: CookieBot, OneTrust, CookieYes, tarteaucitron (free), Klaro (free), Osano, Didomi, Axeptio.\"".to_string(),
            },
            file: None,
            line: None,
            message: "Tracking scripts detected but no cookie consent banner/CMP found. RGPD/GDPR requires explicit user consent before setting analytics cookies.".to_string(),
        }]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_no_tests_detected() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("index.js"), "console.log('hello');").expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::JavaScript]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Advise);
        assert!(findings[0].message.contains("No test framework"));
    }

    #[test]
    fn test_tests_detected_by_config() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("vitest.config.ts"), "export default {}").expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::JavaScript]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_tests_detected_by_directory() {
        let dir = TempDir::new().expect("create temp dir");
        let test_dir = dir.path().join("tests");
        fs::create_dir(&test_dir).expect("create test dir");
        fs::write(test_dir.join("auth.test.js"), "test('works', () => {})").expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::JavaScript]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_tests_detected_by_spec_file() {
        let dir = TempDir::new().expect("create temp dir");
        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).expect("create src dir");
        fs::write(src_dir.join("auth.spec.ts"), "describe('auth', () => {})").expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::JavaScript]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_tests_detected_rust_cfg_test() {
        let dir = TempDir::new().expect("create temp dir");
        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).expect("create src dir");
        fs::write(
            src_dir.join("main.rs"),
            "#[cfg(test)]\nmod tests { #[test] fn it_works() {} }",
        )
        .expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::Rust]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_tests_detected_python() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("test_auth.py"), "def test_login(): pass").expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::Python]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_tests_detected_go() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("auth_test.go"),
            "func TestLogin(t *testing.T) {}",
        )
        .expect("write file");

        let findings = check_tests(dir.path(), &[Ecosystem::Go]);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_ci_cd() {
        let dir = TempDir::new().expect("create temp dir");

        let findings = check_ci_cd(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("No CI/CD"));
    }

    #[test]
    fn test_ci_cd_github_actions() {
        let dir = TempDir::new().expect("create temp dir");
        let workflows = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&workflows).expect("create workflows dir");
        fs::write(workflows.join("ci.yml"), "name: CI").expect("write file");

        let findings = check_ci_cd(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ci_cd_gitlab() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join(".gitlab-ci.yml"), "stages: [build]").expect("write file");

        let findings = check_ci_cd(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ci_cd_empty_workflows_dir_not_counted() {
        let dir = TempDir::new().expect("create temp dir");
        let workflows = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&workflows).expect("create workflows dir");
        // Empty directory - no workflow files

        let findings = check_ci_cd(dir.path());
        assert_eq!(findings.len(), 1); // Empty dir doesn't count
    }

    #[test]
    fn test_no_readme() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("index.js"), "").expect("write file");

        let findings = check_documentation(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("No README"));
    }

    #[test]
    fn test_readme_present() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("README.md"), "# My Project").expect("write file");

        let findings = check_documentation(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_dead_deps_detection() {
        let dir = TempDir::new().expect("create temp dir");
        let pkg = r#"{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}"#;
        fs::write(dir.path().join("package.json"), pkg).expect("write pkg");

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).expect("create src");
        fs::write(
            src_dir.join("index.js"),
            "const express = require('express');\nconst app = express();",
        )
        .expect("write src");

        let findings = check_dead_deps_js(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("1 unused"));
    }

    #[test]
    fn test_no_dead_deps() {
        let dir = TempDir::new().expect("create temp dir");
        let pkg = r#"{
  "dependencies": {
    "express": "^4.18.0"
  }
}"#;
        fs::write(dir.path().join("package.json"), pkg).expect("write pkg");

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).expect("create src");
        fs::write(src_dir.join("index.js"), "import express from 'express';").expect("write src");

        let findings = check_dead_deps_js(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_duplicate_http_clients() {
        let dir = TempDir::new().expect("create temp dir");
        let pkg = r#"{
  "dependencies": {
    "axios": "^1.0.0",
    "node-fetch": "^3.0.0",
    "express": "^4.18.0"
  }
}"#;
        fs::write(dir.path().join("package.json"), pkg).expect("write pkg");

        let findings = analyze_js_stack(dir.path());
        let http_finding = findings
            .iter()
            .find(|f| matches!(&f.kind, FindingKind::ProjectAdvice { advice_id, .. } if advice_id == "DUPLICATE_HTTP_CLIENTS"));
        assert!(http_finding.is_some());
    }

    #[test]
    fn test_deprecated_dep_request() {
        let dir = TempDir::new().expect("create temp dir");
        let pkg = r#"{
  "dependencies": {
    "request": "^2.88.0",
    "express": "^4.18.0"
  }
}"#;
        fs::write(dir.path().join("package.json"), pkg).expect("write pkg");

        let findings = analyze_js_stack(dir.path());
        let deprecated = findings.iter().find(|f| {
            matches!(&f.kind, FindingKind::ProjectAdvice { advice_id, .. } if advice_id == "DEPRECATED_DEP_REQUEST")
        });
        assert!(deprecated.is_some());
    }

    #[test]
    fn test_extract_dependency_names() {
        let json = r#"{
  "name": "test",
  "dependencies": {
    "express": "^4.18.0",
    "@nestjs/core": "^10.0.0"
  },
  "devDependencies": {
    "vitest": "^1.0.0",
    "@types/node": "^20.0.0"
  }
}"#;
        let deps = extract_dependency_names(json);
        assert!(deps.contains(&"express".to_string()));
        assert!(deps.contains(&"@nestjs/core".to_string()));
        assert!(deps.contains(&"vitest".to_string()));
        // @types/* should be excluded
        assert!(!deps.contains(&"@types/node".to_string()));
    }

    #[test]
    fn test_extract_dependency_names_empty() {
        let json = r#"{ "name": "test" }"#;
        let deps = extract_dependency_names(json);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_scoped_dep_import_detected() {
        let dir = TempDir::new().expect("create temp dir");
        let pkg = r#"{
  "dependencies": {
    "@nestjs/core": "^10.0.0",
    "@nestjs/common": "^10.0.0"
  }
}"#;
        fs::write(dir.path().join("package.json"), pkg).expect("write pkg");

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).expect("create src");
        fs::write(
            src_dir.join("main.ts"),
            "import { NestFactory } from '@nestjs/core';",
        )
        .expect("write src");

        let findings = check_dead_deps_js(dir.path());
        // @nestjs/core is used, @nestjs/common is not
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("1 unused"));
    }

    #[test]
    fn test_full_analyze_empty_project() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("package.json"), "{}").expect("write pkg");

        let findings = analyze_project(
            dir.path(),
            &[Ecosystem::JavaScript],
            &["security".to_string()],
        );
        // Should have at least: NO_TESTS, NO_CI_CD, NO_README
        let advice_ids: Vec<&str> = findings
            .iter()
            .filter_map(|f| match &f.kind {
                FindingKind::ProjectAdvice { advice_id, .. } => Some(advice_id.as_str()),
                _ => None,
            })
            .collect();

        assert!(advice_ids.contains(&"NO_TESTS"));
        assert!(advice_ids.contains(&"NO_CI_CD"));
        assert!(advice_ids.contains(&"NO_README"));
    }

    #[test]
    fn test_full_analyze_complete_project() {
        let dir = TempDir::new().expect("create temp dir");

        // Has package.json with deps
        let pkg = r#"{ "dependencies": { "express": "^4.18.0" } }"#;
        fs::write(dir.path().join("package.json"), pkg).expect("write pkg");

        // Has README
        fs::write(dir.path().join("README.md"), "# Project").expect("write readme");

        // Has tests
        fs::write(dir.path().join("vitest.config.ts"), "export default {}").expect("write vitest");

        // Has CI
        let workflows = dir.path().join(".github").join("workflows");
        fs::create_dir_all(&workflows).expect("create workflows");
        fs::write(workflows.join("ci.yml"), "name: CI").expect("write ci");

        // Has ESLint config with no-console (console strip mechanism)
        fs::write(
            dir.path().join("eslint.config.js"),
            r#"export default [{ rules: { "no-console": "error" } }]"#,
        )
        .expect("write eslint");

        // Has source that uses express
        let src = dir.path().join("src");
        fs::create_dir(&src).expect("create src");
        fs::write(src.join("app.js"), "const express = require('express');").expect("write src");

        let findings = analyze_project(
            dir.path(),
            &[Ecosystem::JavaScript],
            &["security".to_string()],
        );

        // Well-configured project should have no advisories
        // (except maybe deprecated deps if we had any)
        let structural_advices: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                matches!(
                    &f.kind,
                    FindingKind::ProjectAdvice { advice_id, .. }
                    if matches!(advice_id.as_str(), "NO_TESTS" | "NO_CI_CD" | "NO_README" | "DEAD_DEPENDENCIES" | "NO_CONSOLE_STRIP")
                )
            })
            .collect();

        assert!(
            structural_advices.is_empty(),
            "Complete project should not have structural advisories, got: {:?}",
            structural_advices
                .iter()
                .map(|f| &f.message)
                .collect::<Vec<_>>()
        );
    }

    // ─── NO_CONSOLE_STRIP tests ───

    #[test]
    fn test_no_console_strip_detected() {
        let dir = TempDir::new().expect("create temp dir");
        // JS project without any console strip mechanism
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "express": "^4.18.0" } }"#,
        )
        .expect("write pkg");

        let findings = check_console_strip(dir.path());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("console.log stripping"));
    }

    #[test]
    fn test_console_strip_eslint_no_console() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "express": "^4.18.0" } }"#,
        )
        .expect("write pkg");
        fs::write(
            dir.path().join("eslint.config.js"),
            r#"export default [{ rules: { "no-console": "error" } }]"#,
        )
        .expect("write eslint");

        let findings = check_console_strip(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_console_strip_structured_logger() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "express": "^4.18.0", "pino": "^8.0.0" } }"#,
        )
        .expect("write pkg");

        let findings = check_console_strip(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_console_strip_vite_drop_console() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("package.json"),
            r#"{ "dependencies": { "express": "^4.18.0" } }"#,
        )
        .expect("write pkg");
        fs::write(
            dir.path().join("vite.config.ts"),
            r#"export default defineConfig({ build: { terserOptions: { compress: { drop_console: true } } } })"#,
        )
        .expect("write vite");

        let findings = check_console_strip(dir.path());
        assert!(findings.is_empty());
    }
}
