use serde::Serialize;
use std::fmt;
use std::path::PathBuf;

/// Severity levels for findings, ordered by strictness.
/// BLOCK: build fails (exit 1)
/// Warn: build passes unless --strict (exit 0 or 1)
/// Advise: build passes unless --full (exit 0 or 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Advise,
    Warn,
    Block,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Block => write!(f, "BLOCK"),
            Severity::Warn => write!(f, "WARN"),
            Severity::Advise => write!(f, "ADVISE"),
        }
    }
}

/// What kind of finding this is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FindingKind {
    /// A required external tool is missing from PATH.
    ToolMissing {
        tool_name: String,
        install_hint: String,
    },
    /// A required external tool ran and found problems.
    ToolFailed { tool_name: String, output: String },
    /// An internal couche 1 rule matched.
    RuleViolation {
        rule_id: String,
        cwe: Vec<String>,
        code_snippet: String,
        fix: String,
    },
    /// A project analysis advisory (couche 3).
    ProjectAdvice { advice_id: String, question: String },
}

/// A single finding produced by the scan pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: FindingKind,
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub message: String,
}

/// Detected ecosystems in the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Ecosystem {
    JavaScript,
    Python,
    Go,
    Rust,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::JavaScript => write!(f, "JavaScript/TypeScript"),
            Ecosystem::Python => write!(f, "Python"),
            Ecosystem::Go => write!(f, "Go"),
            Ecosystem::Rust => write!(f, "Rust"),
        }
    }
}

/// An external tool that ai-rsk requires or recommends.
#[derive(Debug, Clone)]
pub struct ExternalTool {
    pub name: String,
    pub binary: String,
    pub required: bool,
    pub install_hint: String,
    /// Shell commands to try for auto-installation (tried in order, first success wins).
    pub install_commands: Vec<Vec<String>>,
    /// Shell commands to try for auto-update (tried in order, first success wins).
    /// Multiple commands handle the case where the tool was installed via different package managers.
    pub update_commands: Vec<Vec<String>>,
    /// GitHub release info for direct binary download (last-resort fallback).
    /// Format: (owner/repo, asset pattern with {os}, {arch}, {ext} placeholders).
    pub github_release: Option<(String, String)>,
}

/// Status of an external tool check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ToolStatus {
    Installed { version: String },
    Missing,
}

/// Result of the full scan pipeline.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub ecosystems: Vec<Ecosystem>,
    pub tool_statuses: Vec<(String, ToolStatus)>,
    pub ignore_count: usize,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            ecosystems: Vec::new(),
            tool_statuses: Vec::new(),
            ignore_count: 0,
        }
    }

    /// Count findings at a given severity level.
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Write a persistent report file (.ai-rsk/report.md) to the project directory.
    /// The LLM is OBLIGATED to read this file before coding. It survives context compaction.
    pub fn write_report(
        &self,
        project_path: &std::path::Path,
        strict: bool,
        full: bool,
    ) -> std::io::Result<()> {
        let report_dir = project_path.join(".ai-rsk");
        if !report_dir.exists() {
            std::fs::create_dir_all(&report_dir)?;
        }

        let blocks = self.count_by_severity(Severity::Block);
        let warns = self.count_by_severity(Severity::Warn);
        let advises = self.count_by_severity(Severity::Advise);
        let exit = self.exit_code(strict, full);
        let mode = if full {
            "--full"
        } else if strict {
            "--strict"
        } else {
            "default"
        };
        let status = if exit == 0 { "PASS" } else { "BLOCKED" };
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");

        let mut report = String::new();
        report.push_str("# ai-rsk Security Report\n\n");
        report.push_str(&format!(
            "**Status: {}** | Exit code: {} | Mode: {}\n",
            status, exit, mode
        ));
        report.push_str(&format!(
            "**Scan date:** {} | **BLOCK:** {} | **WARN:** {} | **ADVISE:** {}\n\n",
            timestamp, blocks, warns, advises
        ));

        if exit != 0 {
            report.push_str("## MANDATORY - READ THIS BEFORE DOING ANYTHING\n\n");
            report.push_str("The build is **BLOCKED**. You MUST fix every BLOCK finding below before the build can pass.\n");
            report.push_str("Do NOT work on features, refactoring, or anything else until this report is clean.\n");
            report.push_str("After fixing, run `ai-rsk scan` again to regenerate this report.\n\n");
        }

        // Group findings by severity
        for severity in &[Severity::Block, Severity::Warn, Severity::Advise] {
            let findings_at_severity: Vec<_> = self
                .findings
                .iter()
                .filter(|f| f.severity == *severity)
                .collect();
            if findings_at_severity.is_empty() {
                continue;
            }

            let label = match severity {
                Severity::Block => "BLOCK - Must fix (build fails)",
                Severity::Warn => "WARN - Should fix (build fails with --strict)",
                Severity::Advise => "ADVISE - Consider fixing (build fails with --full)",
            };
            report.push_str(&format!("## {}\n\n", label));

            for (i, finding) in findings_at_severity.iter().enumerate() {
                report.push_str(&format!("### {}. {}\n\n", i + 1, finding.message));

                if let Some(ref file) = finding.file {
                    let loc = match finding.line {
                        Some(line) => format!("{}:{}", file.display(), line),
                        None => format!("{}", file.display()),
                    };
                    report.push_str(&format!("**File:** `{}`\n\n", loc));
                }

                match &finding.kind {
                    FindingKind::ToolMissing {
                        tool_name,
                        install_hint,
                    } => {
                        report.push_str(&format!("**Tool:** {}\n", tool_name));
                        report.push_str(&format!("**Install:** `{}`\n\n", install_hint));
                    }
                    FindingKind::RuleViolation {
                        rule_id,
                        cwe,
                        code_snippet,
                        fix,
                    } => {
                        if !cwe.is_empty() {
                            report.push_str(&format!(
                                "**Rule:** {} ({})\n",
                                rule_id,
                                cwe.join(", ")
                            ));
                        } else {
                            report.push_str(&format!("**Rule:** {}\n", rule_id));
                        }
                        if !code_snippet.is_empty() {
                            report.push_str(&format!("**Code:** `{}`\n", code_snippet));
                        }
                        if !fix.is_empty() {
                            report.push_str("\n**Fix:**\n");
                            report.push_str("```\n");
                            report.push_str(fix.trim());
                            report.push_str("\n```\n\n");
                        }
                    }
                    FindingKind::ProjectAdvice {
                        advice_id,
                        question,
                    } => {
                        report.push_str(&format!("**ID:** {}\n", advice_id));
                        report.push_str(&format!("{}\n\n", question));
                    }
                    FindingKind::ToolFailed { tool_name, output } => {
                        report.push_str(&format!("**Tool:** {} failed\n", tool_name));
                        report.push_str("```\n");
                        for line in output.lines().take(20) {
                            report.push_str(line);
                            report.push('\n');
                        }
                        report.push_str("```\n\n");
                    }
                }
            }
        }

        if self.ignore_count > 0 {
            report.push_str(&format!(
                "## Ignores\n\n{} `ai-rsk-ignore` comments found.\n\n",
                self.ignore_count
            ));
        }

        report.push_str("---\n");
        report.push_str(
            "*This report is regenerated on every `ai-rsk scan`. Do not edit manually.*\n",
        );
        report.push_str(&format!(
            "*Generated by ai-rsk v{}*\n",
            env!("CARGO_PKG_VERSION")
        ));

        std::fs::write(report_dir.join("report.md"), report)?;
        Ok(())
    }

    /// Determine exit code based on findings and strictness flags.
    /// Exit 0 = pass, 1 = blocked, 2 = internal error (handled elsewhere).
    pub fn exit_code(&self, strict: bool, full: bool) -> i32 {
        for finding in &self.findings {
            match finding.severity {
                Severity::Block => return 1,
                Severity::Warn if strict => return 1,
                Severity::Advise if full => return 1,
                _ => {}
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_no_findings() {
        let result = ScanResult::new();
        assert_eq!(result.exit_code(false, false), 0);
        assert_eq!(result.exit_code(true, false), 0);
        assert_eq!(result.exit_code(true, true), 0);
    }

    #[test]
    fn test_exit_code_block_always_fails() {
        let mut result = ScanResult::new();
        result.findings.push(Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolMissing {
                tool_name: "semgrep".to_string(),
                install_hint: "pip install semgrep".to_string(),
            },
            file: None,
            line: None,
            message: "semgrep not found".to_string(),
        });
        assert_eq!(result.exit_code(false, false), 1);
        assert_eq!(result.exit_code(true, false), 1);
        assert_eq!(result.exit_code(true, true), 1);
    }

    #[test]
    fn test_exit_code_warn_only_with_strict() {
        let mut result = ScanResult::new();
        result.findings.push(Finding {
            severity: Severity::Warn,
            kind: FindingKind::RuleViolation {
                rule_id: "MISSING_CSP".to_string(),
                cwe: vec!["CWE-693".to_string()],
                code_snippet: String::new(),
                fix: "Add CSP header".to_string(),
            },
            file: Some(PathBuf::from("server.js")),
            line: Some(1),
            message: "No CSP header detected".to_string(),
        });
        assert_eq!(result.exit_code(false, false), 0);
        assert_eq!(result.exit_code(true, false), 1);
        assert_eq!(result.exit_code(true, true), 1);
    }

    #[test]
    fn test_exit_code_advise_only_with_full() {
        let mut result = ScanResult::new();
        result.findings.push(Finding {
            severity: Severity::Advise,
            kind: FindingKind::ProjectAdvice {
                advice_id: "NO_TESTS".to_string(),
                question: "Do you want me to set up a test framework?".to_string(),
            },
            file: None,
            line: None,
            message: "No test framework detected".to_string(),
        });
        assert_eq!(result.exit_code(false, false), 0);
        assert_eq!(result.exit_code(true, false), 0);
        assert_eq!(result.exit_code(true, true), 1);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Block > Severity::Warn);
        assert!(Severity::Warn > Severity::Advise);
    }

    #[test]
    fn test_count_by_severity() {
        let mut result = ScanResult::new();
        result.findings.push(Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolMissing {
                tool_name: "gitleaks".to_string(),
                install_hint: "brew install gitleaks".to_string(),
            },
            file: None,
            line: None,
            message: "gitleaks not found".to_string(),
        });
        result.findings.push(Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolMissing {
                tool_name: "semgrep".to_string(),
                install_hint: "pip install semgrep".to_string(),
            },
            file: None,
            line: None,
            message: "semgrep not found".to_string(),
        });
        result.findings.push(Finding {
            severity: Severity::Warn,
            kind: FindingKind::RuleViolation {
                rule_id: "MISSING_CSP".to_string(),
                cwe: vec![],
                code_snippet: String::new(),
                fix: String::new(),
            },
            file: None,
            line: None,
            message: "No CSP".to_string(),
        });
        assert_eq!(result.count_by_severity(Severity::Block), 2);
        assert_eq!(result.count_by_severity(Severity::Warn), 1);
        assert_eq!(result.count_by_severity(Severity::Advise), 0);
    }

    #[test]
    fn test_ecosystem_display() {
        assert_eq!(
            format!("{}", Ecosystem::JavaScript),
            "JavaScript/TypeScript"
        );
        assert_eq!(format!("{}", Ecosystem::Python), "Python");
        assert_eq!(format!("{}", Ecosystem::Go), "Go");
        assert_eq!(format!("{}", Ecosystem::Rust), "Rust");
    }
}
