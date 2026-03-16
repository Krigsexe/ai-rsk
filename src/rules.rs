use crate::embedded_rules::EMBEDDED_RULES;
use crate::types::{Finding, FindingKind, Severity};
use anyhow::{Context, Result};
use regex::RegexBuilder;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A rule as loaded from a YAML file.
#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub severity: String,
    pub cwe: Vec<String>,
    pub file_patterns: Vec<String>,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    pub message: String,
    pub fix: String,
    // Negation: if this pattern IS found, the rule does NOT fire.
    // Used for "absence detection" (e.g., express() without app.disable('x-powered-by')).
    #[serde(default)]
    pub negation: bool,
    #[serde(default)]
    pub negation_pattern: Option<String>,
    // Agnostic negation: when true (default), the negation pattern is checked project-wide.
    // When false, the negation pattern is checked per-file only.
    // Use false for rules where each occurrence must individually satisfy the negation
    // (e.g., each .cookie() call must have httpOnly, not just one cookie in the project).
    #[serde(default = "default_agnostic_negation")]
    pub agnostic_negation: bool,
    // Per-rule path exclusions: if the file's relative path starts with any of these prefixes,
    // the rule is skipped for that file. Used to distinguish client vs server code.
    // Example: ["api/", "server/", "backend/"] to skip server-side files for client-only rules.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    // Category determines which compliance profile activates this rule.
    // Values: "security" (default, always active), "gdpr", "ai-act", "seo", "a11y".
    // Rules with non-security categories only fire when the corresponding profile is active.
    #[serde(default = "default_category")]
    pub category: String,
    // Mode filter: if set, the rule only fires in the specified mode.
    // Values: None (always active), "production", "development".
    #[serde(default)]
    pub mode: Option<String>,
}

/// Directories to exclude from scanning (code that isn't ours + test code).
/// Test directories are excluded because test files are not part of the
/// production build - findings in tests are false positives by definition.
const EXCLUDED_DIRS: &[&str] = &[
    // Third-party / generated / bundled
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
    // Test directories
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "__mocks__",
    "fixtures",
    // Example / documentation code (not production)
    "examples",
    "example",
    "docs",
    "docs_src",
    "doc",
    "samples",
    "demo",
    "demos",
];

/// Load all YAML rules from a directory on disk.
/// Returns an empty Vec if the directory does not exist.
fn load_rules_from_disk(rules_dir: &Path) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    if !rules_dir.exists() {
        return Ok(rules);
    }

    for entry in WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
    {
        let content = std::fs::read_to_string(entry.path())
            .with_context(|| format!("Failed to read rule file: {}", entry.path().display()))?;
        let rule: Rule = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse rule file: {}", entry.path().display()))?;
        rules.push(rule);
    }

    Ok(rules)
}

/// Load rules embedded in the binary at compile time.
/// These are the YAML rules from rules/ compiled via include_str!.
fn load_embedded_rules() -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    for (filename, content) in EMBEDDED_RULES {
        let rule: Rule = serde_yaml::from_str(content)
            .with_context(|| format!("Failed to parse embedded rule: {}", filename))?;
        rules.push(rule);
    }

    Ok(rules)
}

/// Load all YAML rules.
/// Priority: disk rules/ directory (development) → embedded rules (installed binary).
pub fn load_rules(rules_dir: &Path) -> Result<Vec<Rule>> {
    let disk_rules = load_rules_from_disk(rules_dir)?;
    if !disk_rules.is_empty() {
        return Ok(disk_rules);
    }

    // No rules on disk - use embedded rules compiled into the binary
    load_embedded_rules()
}

/// Check if a file path matches any of the rule's file patterns.
fn matches_file_pattern(file_path: &Path, patterns: &[String]) -> bool {
    let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };

    for pattern in patterns {
        // Simple glob: *.js matches any .js file
        if let Some(ext) = pattern.strip_prefix("*.")
            && file_name.ends_with(&format!(".{}", ext))
        {
            return true;
        }
    }
    false
}

/// Check if a file should be excluded from scanning.
/// Excludes: third-party dirs, test dirs, and test files by name pattern.
fn is_excluded(path: &Path) -> bool {
    // Check directory components
    if path.components().any(|c| {
        if let std::path::Component::Normal(name) = c
            && let Some(name_str) = name.to_str()
        {
            return EXCLUDED_DIRS.contains(&name_str);
        }
        false
    }) {
        return true;
    }

    // Check test file name patterns (e.g., auth.test.js, auth.spec.ts, test_auth.py)
    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && (name.contains(".test.") || name.contains(".spec.") || name.starts_with("test_"))
    {
        return true;
    }

    // Exclude minified files (generated code, not source - always false positives)
    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && (name.ends_with(".min.js") || name.ends_with(".min.css") || name.ends_with(".min.mjs"))
    {
        return true;
    }

    false
}

/// Detect if a file is minified by checking if the first line exceeds a threshold.
/// Minified JS/CSS files have extremely long lines (often 100K+ characters on a single line).
/// No human-written source code has lines longer than 500 characters.
fn is_minified(content: &str) -> bool {
    if let Some(first_line) = content.lines().next() {
        first_line.len() > 500
    } else {
        false
    }
}

/// Parse the ai-rsk-ignore comment on the line before a match.
/// Returns Some(justification) if valid ignore found, None otherwise.
fn check_ignore(lines: &[&str], line_idx: usize, rule_id: &str) -> Option<String> {
    if line_idx == 0 {
        return None;
    }

    let prev_line = lines[line_idx - 1].trim();

    // Format: // ai-rsk-ignore RULE_ID -- justification
    // Also accept: # ai-rsk-ignore RULE_ID -- justification
    let ignore_markers = [format!("ai-rsk-ignore {}", rule_id)];

    for marker in &ignore_markers {
        if prev_line.contains(marker.as_str()) {
            // Check for justification after --
            if let Some(pos) = prev_line.find("--") {
                let justification = prev_line[pos + 2..].trim();
                if !justification.is_empty() {
                    return Some(justification.to_string());
                }
            }
            // Ignore without justification = invalid, don't suppress
            return None;
        }
    }
    None
}

/// Scan all files in a project against all loaded rules.
/// Returns findings and ignore count.
/// `extra_excludes` contains additional directory/file patterns from ai-rsk.config.yaml.
pub fn scan_files(
    project_path: &Path,
    rules: &[Rule],
    extra_excludes: &[String],
) -> Result<(Vec<Finding>, usize)> {
    let mut findings = Vec::new();
    let mut ignore_count: usize = 0;

    // ── AGNOSTIC NEGATION PRE-SCAN ──────────────────────────────────────
    // For negation rules (e.g., "express() without helmet"), the negation
    // pattern must be checked PROJECT-WIDE, not per-file. If helmet() is
    // called anywhere in the project, the rule is satisfied for ALL files.
    // This prevents false positives on routers/tests that use express()
    // without mentioning helmet - helmet protects the whole server.
    // Only include agnostic negation rules in the project-wide pre-scan.
    // Per-file negation rules (agnostic_negation: false) are checked during the main scan.
    let negation_rules: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.negation && r.agnostic_negation)
        .collect();
    let mut globally_satisfied_rules: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    if !negation_rules.is_empty() {
        for entry in WalkDir::new(project_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            if is_excluded(file_path) {
                continue;
            }
            if !extra_excludes.is_empty() {
                let rel = file_path.strip_prefix(project_path).unwrap_or(file_path);
                let rel_str = rel.to_string_lossy();
                if extra_excludes.iter().any(|excl| {
                    let excl_trimmed = excl.trim_end_matches('/');
                    rel_str.starts_with(excl_trimmed)
                }) {
                    continue;
                }
            }

            // Only read files that match at least one negation rule's file patterns
            let dominated_patterns: Vec<&str> = negation_rules
                .iter()
                .filter(|r| !globally_satisfied_rules.contains(&r.id))
                .filter(|r| matches_file_pattern(file_path, &r.file_patterns))
                .flat_map(|r| r.negation_pattern.as_deref())
                .collect();

            if dominated_patterns.is_empty() {
                continue;
            }

            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => {
                    if is_minified(&c) {
                        continue;
                    }
                    c
                }
                Err(_) => continue,
            };

            // Check each unsatisfied negation rule against this file's content
            for rule in &negation_rules {
                if globally_satisfied_rules.contains(&rule.id) {
                    continue;
                }
                if !matches_file_pattern(file_path, &rule.file_patterns) {
                    continue;
                }
                if let Some(neg_pat) = &rule.negation_pattern {
                    match RegexBuilder::new(neg_pat)
                        .case_insensitive(rule.case_insensitive)
                        .build()
                    {
                        Ok(re) => {
                            if re.is_match(&content) {
                                globally_satisfied_rules.insert(rule.id.clone());
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "WARNING: Invalid negation regex in rule {} pattern '{}': {}",
                                rule.id, neg_pat, e
                            );
                        }
                    }
                }
            }

            // Early exit if all negation rules are satisfied
            if negation_rules
                .iter()
                .all(|r| globally_satisfied_rules.contains(&r.id))
            {
                break;
            }
        }
    }
    // ── END AGNOSTIC NEGATION PRE-SCAN ──────────────────────────────────

    for entry in WalkDir::new(project_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();

        // Skip excluded directories (built-in)
        if is_excluded(file_path) {
            continue;
        }

        // Skip extra exclusions from config
        if !extra_excludes.is_empty() {
            let rel = file_path.strip_prefix(project_path).unwrap_or(file_path);
            let rel_str = rel.to_string_lossy();
            if extra_excludes.iter().any(|excl| {
                let excl_trimmed = excl.trim_end_matches('/');
                rel_str.starts_with(excl_trimmed)
            }) {
                continue;
            }
        }

        for rule in rules {
            // Check if this file matches the rule's file patterns
            if !matches_file_pattern(file_path, &rule.file_patterns) {
                continue;
            }

            // Check per-rule path exclusions (e.g., skip server dirs for client-only rules)
            if !rule.exclude_paths.is_empty() {
                let rel = file_path.strip_prefix(project_path).unwrap_or(file_path);
                let rel_str = rel.to_string_lossy();
                if rule.exclude_paths.iter().any(|excl| {
                    let excl_trimmed = excl.trim_end_matches('/');
                    rel_str.starts_with(excl_trimmed)
                        || rel_str.contains(&format!("/{excl_trimmed}/"))
                        || rel_str.contains(&format!("/{excl_trimmed}"))
                }) {
                    continue;
                }
            }

            // Read file content
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => {
                    // Skip minified files (generated code — first line > 500 chars)
                    if is_minified(&c) {
                        continue;
                    }
                    c
                }
                Err(_) => continue, // Skip binary files or unreadable files
            };

            let lines: Vec<&str> = content.lines().collect();

            // For negation rules with agnostic_negation: true (default),
            // use the project-wide pre-scan result.
            // For negation rules with agnostic_negation: false,
            // check the negation pattern in THIS file only.
            if rule.negation {
                if rule.agnostic_negation {
                    // Agnostic: negation found anywhere in project = rule satisfied
                    if globally_satisfied_rules.contains(&rule.id) {
                        continue;
                    }
                } else {
                    // Per-file: check negation in this file only
                    if let Some(neg_pat) = &rule.negation_pattern {
                        let neg_satisfied = match RegexBuilder::new(neg_pat)
                            .case_insensitive(rule.case_insensitive)
                            .build()
                        {
                            Ok(re) => re.is_match(&content),
                            Err(_) => false,
                        };
                        if neg_satisfied {
                            continue; // This file has the negation pattern - no violation here
                        }
                    }
                }

                let has_positive_match =
                    rule.patterns.iter().any(|pattern| {
                        match RegexBuilder::new(pattern)
                            .case_insensitive(rule.case_insensitive)
                            .build()
                        {
                            Ok(re) => re.is_match(&content),
                            Err(e) => {
                                eprintln!(
                                    "WARNING: Invalid regex in rule {} pattern '{}': {}",
                                    rule.id, pattern, e
                                );
                                false
                            }
                        }
                    });

                if has_positive_match {
                    let rel_path = file_path.strip_prefix(project_path).unwrap_or(file_path);
                    findings.push(Finding {
                        severity: parse_severity(&rule.severity),
                        kind: FindingKind::RuleViolation {
                            rule_id: rule.id.clone(),
                            cwe: rule.cwe.clone(),
                            code_snippet: String::new(),
                            fix: rule.fix.clone(),
                        },
                        file: Some(rel_path.to_path_buf()),
                        line: None,
                        message: rule.message.clone(),
                    });
                }
                continue;
            }

            // Standard pattern matching: check each line.
            // Deduplicate: one finding per rule per line (multiple patterns may match the same line).
            let mut matched_lines: std::collections::HashSet<usize> =
                std::collections::HashSet::new();

            for pattern in &rule.patterns {
                let re = match RegexBuilder::new(pattern)
                    .case_insensitive(rule.case_insensitive)
                    .build()
                {
                    Ok(re) => re,
                    Err(e) => {
                        eprintln!(
                            "WARNING: Invalid regex in rule {} pattern '{}': {}",
                            rule.id, pattern, e
                        );
                        continue;
                    }
                };

                for (line_idx, line) in lines.iter().enumerate() {
                    if matched_lines.contains(&line_idx) {
                        continue; // Already reported for this rule on this line
                    }

                    if re.is_match(line) {
                        // Check for ignore comment
                        if check_ignore(&lines, line_idx, &rule.id).is_some() {
                            ignore_count += 1;
                            matched_lines.insert(line_idx);
                            continue;
                        }

                        let rel_path = file_path.strip_prefix(project_path).unwrap_or(file_path);

                        findings.push(Finding {
                            severity: parse_severity(&rule.severity),
                            kind: FindingKind::RuleViolation {
                                rule_id: rule.id.clone(),
                                cwe: rule.cwe.clone(),
                                code_snippet: line.trim().to_string(),
                                fix: rule.fix.clone(),
                            },
                            file: Some(rel_path.to_path_buf()),
                            line: Some(line_idx + 1),
                            message: rule.message.clone(),
                        });

                        matched_lines.insert(line_idx);
                    }
                }
            }
        }
    }

    Ok((findings, ignore_count))
}

fn default_agnostic_negation() -> bool {
    true
}

fn default_category() -> String {
    "security".to_string()
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "BLOCK" => Severity::Block,
        "WARN" => Severity::Warn,
        "ADVISE" => Severity::Advise,
        _ => Severity::Warn,
    }
}

/// Resolve the rules directory. First check if a `rules/` dir exists
/// next to the binary (for development). Then check the project path.
/// Finally fall back to the compiled-in rules directory.
pub fn find_rules_dir(project_path: &Path) -> PathBuf {
    // Check next to the binary (development mode)
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        let dev_rules = exe_dir.join("../../rules");
        if dev_rules.exists() {
            return dev_rules;
        }
    }

    // Check in the project path (if ai-rsk was cloned into the project)
    let project_rules = project_path.join("rules");
    if project_rules.exists() {
        return project_rules;
    }

    // Fallback: current working directory rules/
    PathBuf::from("rules")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_test_rule() -> Rule {
        Rule {
            id: "TEST_RULE".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-922".to_string()],

            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"localStorage\.setItem\(.*(token|jwt|auth)".to_string()],
            case_insensitive: true,
            message: "Test rule triggered".to_string(),
            fix: "Fix it".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        }
    }

    #[test]
    fn test_matches_file_pattern() {
        assert!(matches_file_pattern(
            Path::new("src/auth.js"),
            &["*.js".to_string()]
        ));
        assert!(matches_file_pattern(
            Path::new("src/auth.tsx"),
            &["*.tsx".to_string()]
        ));
        assert!(!matches_file_pattern(
            Path::new("src/auth.py"),
            &["*.js".to_string()]
        ));
    }

    #[test]
    fn test_is_excluded() {
        assert!(is_excluded(Path::new("project/node_modules/foo/bar.js")));
        assert!(is_excluded(Path::new("project/.git/config")));
        assert!(is_excluded(Path::new("project/dist/bundle.js")));
        assert!(is_excluded(Path::new("project/target/debug/main")));
        assert!(!is_excluded(Path::new("project/src/main.js")));
        assert!(!is_excluded(Path::new("project/lib/utils.js")));
    }

    #[test]
    fn test_scan_vulnerable_localstorage() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let vuln_file = dir.path().join("auth.js");
        fs::write(
            &vuln_file,
            r#"localStorage.setItem('access_token', response.data.token);"#,
        )
        .expect("Failed to write");

        let rules = vec![make_test_rule()];
        let (findings, ignores) = scan_files(dir.path(), &rules, &[]).expect("Scan failed");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Block);
        assert_eq!(ignores, 0);
    }

    #[test]
    fn test_scan_safe_localstorage() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let safe_file = dir.path().join("theme.js");
        fs::write(&safe_file, r#"localStorage.setItem('theme', 'dark');"#)
            .expect("Failed to write");

        let rules = vec![make_test_rule()];
        let (findings, _) = scan_files(dir.path(), &rules, &[]).expect("Scan failed");

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_scan_ignore_with_justification() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let file = dir.path().join("auth.js");
        fs::write(
            &file,
            "// ai-rsk-ignore TEST_RULE -- stores non-sensitive preference key\nlocalStorage.setItem('auth_token', jwt);",
        )
        .expect("Failed to write");

        let rules = vec![make_test_rule()];
        let (findings, ignores) = scan_files(dir.path(), &rules, &[]).expect("Scan failed");

        assert_eq!(findings.len(), 0);
        assert_eq!(ignores, 1);
    }

    #[test]
    fn test_scan_ignore_without_justification_not_suppressed() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let file = dir.path().join("auth.js");
        fs::write(
            &file,
            "// ai-rsk-ignore TEST_RULE\nlocalStorage.setItem('auth_token', jwt);",
        )
        .expect("Failed to write");

        let rules = vec![make_test_rule()];
        let (findings, ignores) = scan_files(dir.path(), &rules, &[]).expect("Scan failed");

        // Ignore without justification is invalid - finding NOT suppressed
        assert_eq!(findings.len(), 1);
        assert_eq!(ignores, 0);
    }

    #[test]
    fn test_scan_skips_node_modules() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let nm_dir = dir.path().join("node_modules").join("some-pkg");
        fs::create_dir_all(&nm_dir).expect("Failed to create dir");
        fs::write(
            nm_dir.join("index.js"),
            r#"localStorage.setItem('auth_token', token);"#,
        )
        .expect("Failed to write");

        let rules = vec![make_test_rule()];
        let (findings, _) = scan_files(dir.path(), &rules, &[]).expect("Scan failed");

        assert_eq!(findings.len(), 0); // node_modules excluded
    }

    #[test]
    fn test_scan_skips_binary_files() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let bin_file = dir.path().join("image.js");
        // Write some invalid UTF-8 bytes
        fs::write(&bin_file, &[0xFF, 0xFE, 0x00, 0x01]).expect("Failed to write");

        let rules = vec![make_test_rule()];
        let (findings, _) = scan_files(dir.path(), &rules, &[]).expect("Scan failed");

        assert_eq!(findings.len(), 0); // Binary file skipped
    }

    fn make_negation_rule() -> Rule {
        Rule {
            id: "TEST_NEGATION".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-497".to_string()],

            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"express\(\)".to_string()],
            case_insensitive: false,
            message: "Express without x-powered-by disabled".to_string(),
            fix: "Use app.disable(\"x-powered-by\")".to_string(),
            negation: true,
            negation_pattern: Some(r#"app\.disable\s*\(\s*['"]x-powered-by"#.to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        }
    }

    #[test]
    fn test_negation_rule_fires_when_negation_absent() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("server.js");
        fs::write(&file, "const app = express();\napp.get(\"/\", handler);").expect("write file");

        let rule = make_negation_rule();
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_negation_rule_silent_when_negation_present() {
        let dir = TempDir::new().expect("create temp dir");
        let file = dir.path().join("server.js");
        let content = [
            "const app = express();",
            "app.disable(\"x-powered-by\");",
            "app.get(\"/\", handler);",
        ]
        .join("\n");
        fs::write(&file, content).expect("write file");

        let rule = make_negation_rule();

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("Scan failed");
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_load_rules_from_real_dir() {
        let rules_dir = Path::new("rules");
        if rules_dir.exists() {
            let rules = load_rules(rules_dir).expect("Failed to load rules");
            assert!(
                !rules.is_empty(),
                "Should load at least one rule from rules/"
            );

            // Verify all rules have required fields
            for rule in &rules {
                assert!(!rule.id.is_empty(), "Rule ID must not be empty");
                assert!(
                    !rule.patterns.is_empty(),
                    "Rule must have at least one pattern"
                );
                assert!(!rule.message.is_empty(), "Rule must have a message");
                assert!(!rule.fix.is_empty(), "Rule must have a fix");
                assert!(!rule.cwe.is_empty(), "Rule must have at least one CWE");
            }
        }
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("BLOCK"), Severity::Block);
        assert_eq!(parse_severity("WARN"), Severity::Warn);
        assert_eq!(parse_severity("ADVISE"), Severity::Advise);
        assert_eq!(parse_severity("block"), Severity::Block);
        assert_eq!(parse_severity("unknown"), Severity::Warn);
    }

    // ─── BEARER_EXPOSED_CLIENT tests ───

    #[test]
    fn test_bearer_exposed_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("api.js"),
            r#"const res = await fetch('/api', { headers: { 'Authorization': 'Bearer ' + token } });"#,
        ).expect("write");

        let rule = Rule {
            id: "BEARER_EXPOSED_CLIENT".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-522".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r#"Authorization['"]\s*:\s*['"]Bearer\s"#.to_string()],
            case_insensitive: false,
            message: "Bearer token exposed".to_string(),
            fix: "Use HttpOnly cookies".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_bearer_safe_credentials_include() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("api.js"),
            r#"const res = await fetch('/api', { credentials: 'include' });"#,
        )
        .expect("write");

        let rule = Rule {
            id: "BEARER_EXPOSED_CLIENT".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-522".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r#"Authorization['"]\s*:\s*['"]Bearer\s"#.to_string()],
            case_insensitive: false,
            message: "Bearer token exposed".to_string(),
            fix: "Use HttpOnly cookies".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── CLIENT_SIDE_AUTH_ONLY tests ───

    #[test]
    fn test_client_auth_only_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("guard.js"),
            "if (!isAuthenticated) { redirect('/login'); }",
        )
        .expect("write");

        let rule = Rule {
            id: "CLIENT_SIDE_AUTH_ONLY".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-602".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"if\s*\(\s*!?(isLoggedIn|isAuthenticated|isAdmin|isAuth|loggedIn|authenticated)\s*[)&|]".to_string(),
            ],
            case_insensitive: true,
            message: "Client-side auth check".to_string(),
            fix: "Server-side middleware".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_client_auth_safe_server_middleware() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("middleware.js"),
            "const decoded = jwt.verify(req.cookies.token, SECRET);",
        )
        .expect("write");

        let rule = Rule {
            id: "CLIENT_SIDE_AUTH_ONLY".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-602".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"if\s*\(\s*!?(isLoggedIn|isAuthenticated|isAdmin|isAuth|loggedIn|authenticated)\s*[)&|]".to_string(),
            ],
            case_insensitive: true,
            message: "Client-side auth check".to_string(),
            fix: "Server-side middleware".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── POSTMESSAGE_NO_ORIGIN tests ───

    #[test]
    fn test_postmessage_no_origin_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("widget.js"),
            "window.addEventListener('message', (event) => { processData(event.data); });",
        )
        .expect("write");

        let rule = Rule {
            id: "POSTMESSAGE_NO_ORIGIN".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-346".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"addEventListener\s*\(\s*['\x22`]message['\x22`]".to_string()],
            case_insensitive: false,
            message: "postMessage without origin check".to_string(),
            fix: "Check event.origin".to_string(),
            negation: true,
            negation_pattern: Some(r"event\.origin|e\.origin".to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_postmessage_with_origin_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("widget.js"),
            "window.addEventListener('message', (event) => { if (event.origin !== 'https://safe.com') return; });",
        ).expect("write");

        let rule = Rule {
            id: "POSTMESSAGE_NO_ORIGIN".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-346".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"addEventListener\s*\(\s*['\x22`]message['\x22`]".to_string()],
            case_insensitive: false,
            message: "postMessage without origin check".to_string(),
            fix: "Check event.origin".to_string(),
            negation: true,
            negation_pattern: Some(r"event\.origin|e\.origin".to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── CONSOLE_LOG_SENSITIVE tests ───

    #[test]
    fn test_console_log_sensitive_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("server.js"),
            "console.log(req.headers);\nconsole.log('debug', req.body);",
        )
        .expect("write");

        let rule = Rule {
            id: "CONSOLE_LOG_SENSITIVE".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-532".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"console\.(log|info|debug|warn|error)\s*\(.*(req\.body|req\.headers|req\.cookies|request\.body|request\.headers)".to_string(),
            ],
            case_insensitive: true,
            message: "Sensitive data logged".to_string(),
            fix: "Use structured logger".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 2); // Both lines match
    }

    #[test]
    fn test_console_log_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("server.js"),
            "console.log('Server started on port', port);\nlogger.info({ userId: user.id }, 'Login');",
        ).expect("write");

        let rule = Rule {
            id: "CONSOLE_LOG_SENSITIVE".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-532".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"console\.(log|info|debug|warn|error)\s*\(.*(req\.body|req\.headers|req\.cookies)"
                    .to_string(),
                r"console\.(log|info|debug|warn|error)\s*\(.*\b(password|secret|token|apiKey)"
                    .to_string(),
            ],
            case_insensitive: true,
            message: "Sensitive data logged".to_string(),
            fix: "Use structured logger".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── JWT_SENSITIVE_PAYLOAD tests ───

    #[test]
    fn test_jwt_sensitive_payload_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("auth.js"),
            "const token = jwt.sign({ userId: 1, email: user.email, password: hash }, secret);",
        )
        .expect("write");

        let rule = Rule {
            id: "JWT_SENSITIVE_PAYLOAD".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-312".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"jwt\.sign\s*\(\s*\{[^}]*(password|passwd|secret|credit.?card|ssn|social.?security|address|phone|email|salary|bank)".to_string(),
            ],
            case_insensitive: true,
            message: "Sensitive data in JWT".to_string(),
            fix: "Minimal payload".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_jwt_minimal_payload_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("auth.js"),
            "const token = jwt.sign({ sub: user.id, jti: uuidv4() }, secret, { expiresIn: '15m' });",
        ).expect("write");

        let rule = Rule {
            id: "JWT_SENSITIVE_PAYLOAD".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-312".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"jwt\.sign\s*\(\s*\{[^}]*(password|passwd|secret|credit.?card|ssn|social.?security|address|phone|email|salary|bank)".to_string(),
            ],
            case_insensitive: true,
            message: "Sensitive data in JWT".to_string(),
            fix: "Minimal payload".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── MISSING_CSP tests ───

    #[test]
    fn test_missing_csp_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("server.js"),
            "const app = express();\napp.use(cors());\napp.listen(3000);",
        )
        .expect("write");

        let rule = Rule {
            id: "MISSING_CSP".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-693".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"(app|server|router)\.(use|get|listen)\s*\(".to_string()],
            case_insensitive: true,
            message: "No CSP header".to_string(),
            fix: "Add CSP".to_string(),
            negation: true,
            negation_pattern: Some(
                r"content-security-policy|contentSecurityPolicy|helmet\s*\(|csp\s*\(".to_string(),
            ),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn test_csp_present_with_helmet_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("server.js"),
            "const app = express();\napp.use(helmet());\napp.listen(3000);",
        )
        .expect("write");

        let rule = Rule {
            id: "MISSING_CSP".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-693".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"(app|server|router)\.(use|get|listen)\s*\(".to_string()],
            case_insensitive: true,
            message: "No CSP header".to_string(),
            fix: "Add CSP".to_string(),
            negation: true,
            negation_pattern: Some(
                r"content-security-policy|contentSecurityPolicy|helmet\s*\(|csp\s*\(".to_string(),
            ),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── Deduplication test ───

    #[test]
    fn test_dedup_multiple_patterns_same_line() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("auth.js"),
            "const t = jwt.sign({ userId: 1, email: u.email, password: hash }, s);",
        )
        .expect("write");

        let rule = Rule {
            id: "DEDUP_TEST".to_string(),
            severity: "BLOCK".to_string(),
            cwe: vec!["CWE-312".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"jwt\.sign\s*\(\s*\{[^}]*email".to_string(),
                r"jwt\.sign\s*\(\s*\{[^}]*password".to_string(),
            ],
            case_insensitive: true,
            message: "Dedup test".to_string(),
            fix: "Fix".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };

        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(
            findings.len(),
            1,
            "Same line should produce only 1 finding per rule"
        );
    }

    // ─── MISSING_HSTS tests ───

    fn make_negation_header_rule(id: &str, neg_pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-693".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"(app|server|router)\.(use|get|listen)\s*\(".to_string()],
            case_insensitive: true,
            message: format!("{} missing", id),
            fix: "Add header".to_string(),
            negation: true,
            negation_pattern: Some(neg_pattern.to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        }
    }

    #[test]
    fn test_missing_hsts_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use(cors());\napp.listen(3000);",
        )
        .expect("write");
        let rule = make_negation_header_rule(
            "MISSING_HSTS",
            r"strict-transport-security|strictTransportSecurity|helmet\s*\(|hsts\s*\(",
        );
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_hsts_present_with_helmet_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use(helmet());\napp.listen(3000);",
        )
        .expect("write");
        let rule = make_negation_header_rule(
            "MISSING_HSTS",
            r"strict-transport-security|strictTransportSecurity|helmet\s*\(|hsts\s*\(",
        );
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── MISSING_XFRAME tests ───

    #[test]
    fn test_missing_xframe_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use(cors());\napp.listen(3000);",
        )
        .expect("write");
        let rule = make_negation_header_rule(
            "MISSING_XFRAME",
            r"x-frame-options|frameguard|frame-ancestors|helmet\s*\(",
        );
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_xframe_manual_header_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use((req, res, next) => { res.setHeader('X-Frame-Options', 'DENY'); next(); });\napp.listen(3000);",
        ).expect("write");
        let rule = make_negation_header_rule(
            "MISSING_XFRAME",
            r"x-frame-options|frameguard|frame-ancestors|helmet\s*\(",
        );
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── MISSING_XCONTENT_TYPE tests ───

    #[test]
    fn test_missing_xcontent_type_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use(cors());\napp.listen(3000);",
        )
        .expect("write");
        let rule = make_negation_header_rule(
            "MISSING_XCONTENT_TYPE",
            r"x-content-type-options|noSniff|nosniff|helmet\s*\(",
        );
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_xcontent_type_with_nosniff_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });\napp.listen(3000);",
        ).expect("write");
        let rule = make_negation_header_rule(
            "MISSING_XCONTENT_TYPE",
            r"x-content-type-options|noSniff|nosniff|helmet\s*\(",
        );
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── BODY_PARSER_NO_LIMIT tests ───

    #[test]
    fn test_body_parser_no_limit_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(dir.path().join("app.js"), "app.use(express.json());").expect("write");
        let rule = Rule {
            id: "BODY_PARSER_NO_LIMIT".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-770".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"express\.json\s*\(\s*\)".to_string()],
            case_insensitive: false,
            message: "No body limit".to_string(),
            fix: "Add limit".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_body_parser_with_limit_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("app.js"),
            "app.use(express.json({ limit: '100kb' }));",
        )
        .expect("write");
        let rule = Rule {
            id: "BODY_PARSER_NO_LIMIT".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-770".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![r"express\.json\s*\(\s*\)".to_string()],
            case_insensitive: false,
            message: "No body limit".to_string(),
            fix: "Add limit".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── MISSING_RATE_LIMIT tests ───

    #[test]
    fn test_missing_rate_limit_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("routes.js"),
            "app.post('/login', loginHandler);",
        )
        .expect("write");
        let rule = Rule {
            id: "MISSING_RATE_LIMIT".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-770".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"(app|router)\.(post|put|patch)\s*\(\s*['\x22`]\s*/(login|signin|auth|register|signup|reset|forgot|verify|otp|token|refresh)".to_string(),
            ],
            case_insensitive: true,
            message: "No rate limit".to_string(),
            fix: "Add rate limiter".to_string(),
            negation: true,
            negation_pattern: Some(r"rateLimit|rate-limit|rateLimiter|slowDown|express-rate-limit|limiter".to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_rate_limit_present_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("routes.js"),
            "const limiter = rateLimit({ windowMs: 900000, max: 10 });\napp.post('/login', limiter, loginHandler);",
        ).expect("write");
        let rule = Rule {
            id: "MISSING_RATE_LIMIT".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-770".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"(app|router)\.(post|put|patch)\s*\(\s*['\x22`]\s*/(login|signin|auth|register|signup|reset|forgot|verify|otp|token|refresh)".to_string(),
            ],
            case_insensitive: true,
            message: "No rate limit".to_string(),
            fix: "Add rate limiter".to_string(),
            negation: true,
            negation_pattern: Some(r"rateLimit|rate-limit|rateLimiter|slowDown|express-rate-limit|limiter".to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── WEBSOCKET_NO_AUTH tests ───

    #[test]
    fn test_websocket_no_auth_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("ws.js"),
            "const wss = new WebSocketServer({ port: 8080 });\nwss.on('connection', (ws) => { ws.send('hello'); });",
        ).expect("write");
        let rule = Rule {
            id: "WEBSOCKET_NO_AUTH".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-306".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"(wss?|WebSocketServer|Server)\s*\(|on\s*\(\s*['\x22`]connection['\x22`]"
                    .to_string(),
            ],
            case_insensitive: true,
            message: "WS no auth".to_string(),
            fix: "Verify auth".to_string(),
            negation: true,
            negation_pattern: Some(
                r"verifyClient|authenticate|token|authorization|auth|jwt\.verify|cookie"
                    .to_string(),
            ),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_websocket_with_verify_client_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("ws.js"),
            "const wss = new WebSocketServer({ port: 8080, verifyClient: authCheck });\nwss.on('connection', (ws) => { ws.send('hello'); });",
        ).expect("write");
        let rule = Rule {
            id: "WEBSOCKET_NO_AUTH".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-306".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"(wss?|WebSocketServer|Server)\s*\(|on\s*\(\s*['\x22`]connection['\x22`]"
                    .to_string(),
            ],
            case_insensitive: true,
            message: "WS no auth".to_string(),
            fix: "Verify auth".to_string(),
            negation: true,
            negation_pattern: Some(
                r"verifyClient|authenticate|token|authorization|auth|jwt\.verify|cookie"
                    .to_string(),
            ),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── SOURCE_MAPS_IN_PROD tests ───

    #[test]
    fn test_source_maps_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("webpack.config.js"),
            "module.exports = { devtool: 'source-map', entry: './src/index.js' };",
        )
        .expect("write");
        let rule = Rule {
            id: "SOURCE_MAPS_IN_PROD".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-540".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r#"devtool\s*:\s*['"`](source-map|eval-source-map|cheap-source-map|inline-source-map)"#.to_string(),
            ],
            case_insensitive: false,
            message: "Source maps in prod".to_string(),
            fix: "Disable".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_source_maps_disabled_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("webpack.config.js"),
            "module.exports = { devtool: false, entry: './src/index.js' };",
        )
        .expect("write");
        let rule = Rule {
            id: "SOURCE_MAPS_IN_PROD".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-540".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r#"devtool\s*:\s*['"`](source-map|eval-source-map|cheap-source-map|inline-source-map)"#.to_string(),
            ],
            case_insensitive: false,
            message: "Source maps in prod".to_string(),
            fix: "Disable".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── WINDOW_OPENER_NO_NOOPENER tests ───

    #[test]
    fn test_window_opener_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("page.html"),
            r#"<a href="https://external.com" target="_blank">Link</a>"#,
        )
        .expect("write");
        let rule = Rule {
            id: "WINDOW_OPENER_NO_NOOPENER".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-1022".to_string()],
            file_patterns: vec!["*.html".to_string()],
            patterns: vec![r#"target\s*=\s*['"`]_blank['"`]"#.to_string()],
            case_insensitive: true,
            message: "No noopener".to_string(),
            fix: "Add rel noopener".to_string(),
            negation: true,
            negation_pattern: Some(r#"rel\s*=\s*['"][^'"]*noopener"#.to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_window_opener_with_noopener_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("page.html"),
            r#"<a href="https://external.com" target="_blank" rel="noopener noreferrer">Link</a>"#,
        )
        .expect("write");
        let rule = Rule {
            id: "WINDOW_OPENER_NO_NOOPENER".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-1022".to_string()],
            file_patterns: vec!["*.html".to_string()],
            patterns: vec![r#"target\s*=\s*['"`]_blank['"`]"#.to_string()],
            case_insensitive: true,
            message: "No noopener".to_string(),
            fix: "Add rel noopener".to_string(),
            negation: true,
            negation_pattern: Some(r#"rel\s*=\s*['"][^'"]*noopener"#.to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── CDN_SCRIPT_NO_SRI tests ───

    #[test]
    fn test_cdn_script_no_sri_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("index.html"),
            r#"<script src="https://cdn.example.com/lib.js"></script>"#,
        )
        .expect("write");
        let rule = Rule {
            id: "CDN_SCRIPT_NO_SRI".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-353".to_string()],
            file_patterns: vec!["*.html".to_string()],
            patterns: vec![r#"<script\s+[^>]*src\s*=\s*['"`]https?://"#.to_string()],
            case_insensitive: true,
            message: "CDN script no SRI".to_string(),
            fix: "Add integrity".to_string(),
            negation: true,
            negation_pattern: Some(r#"integrity\s*=\s*['"]sha"#.to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_cdn_script_with_sri_safe() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("index.html"),
            r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>"#,
        ).expect("write");
        let rule = Rule {
            id: "CDN_SCRIPT_NO_SRI".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-353".to_string()],
            file_patterns: vec!["*.html".to_string()],
            patterns: vec![r#"<script\s+[^>]*src\s*=\s*['"`]https?://"#.to_string()],
            case_insensitive: true,
            message: "CDN script no SRI".to_string(),
            fix: "Add integrity".to_string(),
            negation: true,
            negation_pattern: Some(r#"integrity\s*=\s*['"]sha"#.to_string()),
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0);
    }

    // ─── NEGATIVE_BUSINESS_VALUE tests ───

    #[test]
    fn test_negative_business_value_vulnerable() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("cart.js"),
            "const price = req.body.price;\nconst quantity = req.body.quantity;",
        )
        .expect("write");
        let rule = Rule {
            id: "NEGATIVE_BUSINESS_VALUE".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-20".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"(price|amount|total|quantity|qty|cost|fee|charge|payment|balance|credit|discount)\s*[=:]\s*(req\.|request\.|body\.|params\.|query\.)".to_string(),
            ],
            case_insensitive: true,
            message: "Business value from user input".to_string(),
            fix: "Validate server-side".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 2); // price and quantity
    }

    #[test]
    fn test_business_value_validated_still_triggers() {
        // NOTE: This rule detects the ASSIGNMENT pattern, not the validation.
        // It's a WARN, not a BLOCK - it flags the pattern for review.
        // A developer who validates properly can ai-rsk-ignore with justification.
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("cart.js"),
            "const name = req.body.name;\nconst email = req.body.email;",
        )
        .expect("write");
        let rule = Rule {
            id: "NEGATIVE_BUSINESS_VALUE".to_string(),
            severity: "WARN".to_string(),
            cwe: vec!["CWE-20".to_string()],
            file_patterns: vec!["*.js".to_string()],
            patterns: vec![
                r"(price|amount|total|quantity|qty|cost|fee|charge|payment|balance|credit|discount)\s*[=:]\s*(req\.|request\.|body\.|params\.|query\.)".to_string(),
            ],
            case_insensitive: true,
            message: "Business value from user input".to_string(),
            fix: "Validate server-side".to_string(),
            negation: false,
            negation_pattern: None,
            exclude_paths: vec![],
            agnostic_negation: true,
            category: "security".to_string(),
            mode: None,
        };
        let (findings, _) = scan_files(dir.path(), &[rule], &[]).expect("scan");
        assert_eq!(findings.len(), 0); // name and email are not business values
    }

    // ─── Load all real YAML rules test ───

    #[test]
    fn test_load_all_rules() {
        let rules_dir = Path::new("rules");
        if rules_dir.exists() {
            let disk_rules = load_rules(rules_dir).expect("Failed to load rules from disk");
            let embedded_rules = load_embedded_rules().expect("Failed to load embedded rules");

            // Dynamic check: disk rules must match embedded rules count
            assert_eq!(
                disk_rules.len(),
                embedded_rules.len(),
                "Mismatch: {} YAML files on disk vs {} entries in embedded_rules.rs. \
                 Did you forget to add a new rule to embedded_rules.rs?",
                disk_rules.len(),
                embedded_rules.len()
            );

            // Verify all rules have required fields
            for rule in &disk_rules {
                assert!(!rule.id.is_empty(), "Rule ID must not be empty");
                assert!(
                    !rule.patterns.is_empty(),
                    "Rule {} must have at least one pattern",
                    rule.id
                );
                assert!(
                    !rule.message.is_empty(),
                    "Rule {} must have a message",
                    rule.id
                );
                assert!(!rule.fix.is_empty(), "Rule {} must have a fix", rule.id);
                assert!(
                    !rule.cwe.is_empty(),
                    "Rule {} must have at least one CWE",
                    rule.id
                );
            }

            // Verify all embedded rules also parse correctly
            for rule in &embedded_rules {
                assert!(!rule.id.is_empty(), "Embedded rule ID must not be empty");
            }
        }
    }
}
