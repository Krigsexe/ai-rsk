use crate::types::{Ecosystem, Finding, FindingKind, Severity};
use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Result of running an external tool.
struct ToolRun {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// Run a command with timeout, capturing stdout/stderr/exit code.
/// If the command exceeds the timeout, it is killed and an error is returned.
///
/// stdout and stderr are read in separate threads to avoid pipe buffer deadlocks.
/// Without this, a child process that produces more than ~64KB of output will block
/// waiting for the parent to read the pipe, while the parent blocks waiting for
/// the child to exit - classic deadlock.
fn run_command(
    binary: &str,
    args: &[&str],
    working_dir: &Path,
    timeout_secs: u64,
) -> Result<ToolRun> {
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .current_dir(working_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // On Windows, Python-based tools (Semgrep) need UTF-8 encoding forced
    // to prevent crashes on non-UTF-8 system locales.
    // Source: https://semgrep.dev/docs/kb/integrations/semgrep-vs-code-windows
    if cfg!(target_os = "windows") {
        cmd.env("PYTHONUTF8", "1");
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to execute {}", binary))?;

    let child_id = child.id();

    // Read stdout and stderr in separate threads to prevent pipe buffer deadlock.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = std::thread::spawn(move || {
        stdout_pipe
            .map(|mut s| {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut s, &mut buf).ok();
                String::from_utf8_lossy(&buf).to_string()
            })
            .unwrap_or_default()
    });

    let stderr_handle = std::thread::spawn(move || {
        stderr_pipe
            .map(|mut s| {
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut s, &mut buf).ok();
                String::from_utf8_lossy(&buf).to_string()
            })
            .unwrap_or_default()
    });

    // Poll with short sleeps for timeout
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished - collect output from threads
                let stdout = stdout_handle.join().unwrap_or_default();
                let stderr = stderr_handle.join().unwrap_or_default();
                let exit_code = status.code().unwrap_or(1);
                return Ok(ToolRun {
                    stdout,
                    stderr,
                    exit_code,
                });
            }
            Ok(None) => {
                // Still running - check timeout
                if start.elapsed() >= timeout {
                    // Kill the process
                    child.kill().ok();
                    child.wait().ok();
                    anyhow::bail!(
                        "{} (pid {}) timed out after {} seconds. Check if the tool is hanging or increase tool_timeout_seconds in ai-rsk.config.yaml.",
                        binary,
                        child_id,
                        timeout_secs
                    );
                }
                // Sleep briefly before polling again
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                child.kill().ok();
                child.wait().ok();
                anyhow::bail!("Error waiting for {}: {}", binary, e);
            }
        }
    }
}

/// Directories to exclude from external tool scans.
/// Same list as EXCLUDED_DIRS in rules.rs - code that isn't ours.
const SCAN_EXCLUDED_DIRS: &[&str] = &[
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

/// Run semgrep scan on the project.
/// Uses --error to ensure exit code 1 on findings (without it, semgrep returns 0 even with findings).
/// Uses --config=auto to pull community rules.
/// Uses --quiet to reduce noise.
/// Uses --exclude for each directory in SCAN_EXCLUDED_DIRS to avoid scanning third-party code
/// and build artifacts (main cause of Semgrep timeouts on large projects).
/// Verified: semgrep.dev/docs/cli-reference
pub fn run_semgrep(
    project_path: &Path,
    timeout_secs: u64,
    exclude_rules: &[String],
) -> Result<Vec<Finding>> {
    let mut args: Vec<String> = vec![
        "scan".into(),
        "--error".into(),
        "--config=auto".into(),
        "--quiet".into(),
    ];

    for dir in SCAN_EXCLUDED_DIRS {
        args.push(format!("--exclude={}", dir));
    }

    for rule in exclude_rules {
        args.push(format!("--exclude-rule={}", rule));
    }

    args.push(".".into());

    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let result = run_command("semgrep", &args_refs, project_path, timeout_secs)?;

    match result.exit_code {
        0 => Ok(vec![]),
        1 => {
            // Exit 1 with --error = findings detected
            let output = if result.stdout.is_empty() {
                result.stderr
            } else {
                result.stdout
            };
            Ok(vec![Finding {
                severity: Severity::Block,
                kind: FindingKind::ToolFailed {
                    tool_name: "semgrep".to_string(),
                    output: truncate_output(&output, 2000),
                },
                file: None,
                line: None,
                message: "Semgrep found security issues.".to_string(),
            }])
        }
        2 => {
            // Exit 2 = semgrep itself failed
            Ok(vec![Finding {
                severity: Severity::Block,
                kind: FindingKind::ToolFailed {
                    tool_name: "semgrep".to_string(),
                    output: truncate_output(&result.stderr, 1000),
                },
                file: None,
                line: None,
                message: "Semgrep crashed or failed to run.".to_string(),
            }])
        }
        _ => {
            // Exit 3-8 = config/syntax errors
            Ok(vec![Finding {
                severity: Severity::Block,
                kind: FindingKind::ToolFailed {
                    tool_name: "semgrep".to_string(),
                    output: truncate_output(&result.stderr, 1000),
                },
                file: None,
                line: None,
                message: format!(
                    "Semgrep exited with unexpected code {} - check configuration.",
                    result.exit_code
                ),
            }])
        }
    }
}

/// Run gitleaks detect on the project.
/// Uses --exit-code 1 (default) so exit 1 = secrets found.
/// Uses --no-banner to reduce noise.
/// Verified: github.com/gitleaks/gitleaks
pub fn run_gitleaks(project_path: &Path, timeout_secs: u64) -> Result<Vec<Finding>> {
    let result = run_command(
        "gitleaks",
        &["detect", "--source", ".", "--no-banner", "--exit-code", "1"],
        project_path,
        timeout_secs,
    )?;

    match result.exit_code {
        0 => Ok(vec![]),
        1 => {
            let output = if result.stdout.is_empty() {
                result.stderr
            } else {
                result.stdout
            };
            Ok(vec![Finding {
                severity: Severity::Block,
                kind: FindingKind::ToolFailed {
                    tool_name: "gitleaks".to_string(),
                    output: truncate_output(&output, 2000),
                },
                file: None,
                line: None,
                message: "Gitleaks found secrets in the codebase.".to_string(),
            }])
        }
        _ => Ok(vec![Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolFailed {
                tool_name: "gitleaks".to_string(),
                output: truncate_output(&result.stderr, 1000),
            },
            file: None,
            line: None,
            message: format!("Gitleaks exited with unexpected code {}.", result.exit_code),
        }]),
    }
}

/// Run osv-scanner on the project.
/// Exit 0 = no CVE, exit 1 = CVE found, exit 128 = no packages found.
/// Verified: google.github.io/osv-scanner/output/
pub fn run_osv_scanner(project_path: &Path, timeout_secs: u64) -> Result<Vec<Finding>> {
    let result = run_command(
        "osv-scanner",
        &["scan", "--recursive", "."],
        project_path,
        timeout_secs,
    )?;

    match result.exit_code {
        0 => Ok(vec![]),
        1 => {
            let output = if result.stdout.is_empty() {
                result.stderr
            } else {
                result.stdout
            };
            Ok(vec![Finding {
                severity: Severity::Block,
                kind: FindingKind::ToolFailed {
                    tool_name: "osv-scanner".to_string(),
                    output: truncate_output(&output, 2000),
                },
                file: None,
                line: None,
                message: "osv-scanner found known vulnerabilities in dependencies.".to_string(),
            }])
        }
        128 => {
            // No packages found - not an error, just nothing to scan
            Ok(vec![])
        }
        _ => {
            // 127 = general error, 129+ = network/API error
            Ok(vec![Finding {
                severity: Severity::Block,
                kind: FindingKind::ToolFailed {
                    tool_name: "osv-scanner".to_string(),
                    output: truncate_output(&result.stderr, 1000),
                },
                file: None,
                line: None,
                message: format!(
                    "osv-scanner exited with code {} - possible network or configuration error.",
                    result.exit_code
                ),
            }])
        }
    }
}

/// Run knip on a JavaScript/TypeScript project for dead code detection.
/// knip detects: unused dependencies, unused exports, unused files, unused types.
/// If knip is not installed, returns empty - the fallback detection in analyze.rs handles it.
/// Exit 0 = clean, exit 1 = findings, exit 2+ = error.
pub fn run_knip(project_path: &Path, timeout_secs: u64) -> Result<Vec<Finding>> {
    // knip is optional - if not installed, skip silently (analyze.rs has fallback)
    // Check both global PATH and local node_modules/.bin/ (npm install -D knip)
    let knip_binary = if which::which("knip").is_ok() {
        "knip".to_string()
    } else {
        let local_knip = project_path.join("node_modules/.bin/knip");
        if local_knip.exists() {
            local_knip.to_string_lossy().to_string()
        } else {
            return Ok(vec![]);
        }
    };

    let result = run_command(&knip_binary, &["--no-progress"], project_path, timeout_secs)?;

    match result.exit_code {
        0 => Ok(vec![]),
        1 => {
            let output = if result.stdout.is_empty() {
                result.stderr
            } else {
                result.stdout
            };
            Ok(vec![Finding {
                severity: Severity::Warn,
                kind: FindingKind::ToolFailed {
                    tool_name: "knip".to_string(),
                    output: truncate_output(&output, 2000),
                },
                file: None,
                line: None,
                message: "knip found dead code, unused dependencies, or unused exports."
                    .to_string(),
            }])
        }
        _ => Ok(vec![]),
    }
}

/// Check if knip is available (used by analyze.rs to decide whether to run fallback detection).
/// Checks both global PATH and local node_modules/.bin/.
pub fn knip_available(project_path: &Path) -> bool {
    which::which("knip").is_ok() || project_path.join("node_modules/.bin/knip").exists()
}

/// Run all external tools on the project.
/// 3 universal tools always run: Semgrep, Gitleaks, osv-scanner.
/// knip runs on JS/TS projects if installed (fallback detection in analyze.rs if not).
pub fn run_external_tools(
    project_path: &Path,
    ecosystems: &[Ecosystem],
    timeout_secs: u64,
    semgrep_exclude_rules: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    match run_semgrep(project_path, timeout_secs, semgrep_exclude_rules) {
        Ok(f) => findings.extend(f),
        Err(e) => findings.push(Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolFailed {
                tool_name: "semgrep".to_string(),
                output: format!("{}", e),
            },
            file: None,
            line: None,
            message: format!("Failed to run semgrep: {}", e),
        }),
    }

    match run_gitleaks(project_path, timeout_secs) {
        Ok(f) => findings.extend(f),
        Err(e) => findings.push(Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolFailed {
                tool_name: "gitleaks".to_string(),
                output: format!("{}", e),
            },
            file: None,
            line: None,
            message: format!("Failed to run gitleaks: {}", e),
        }),
    }

    match run_osv_scanner(project_path, timeout_secs) {
        Ok(f) => findings.extend(f),
        Err(e) => findings.push(Finding {
            severity: Severity::Block,
            kind: FindingKind::ToolFailed {
                tool_name: "osv-scanner".to_string(),
                output: format!("{}", e),
            },
            file: None,
            line: None,
            message: format!("Failed to run osv-scanner: {}", e),
        }),
    }

    // knip for JS/TS projects - dead code, unused deps, unused exports
    if ecosystems.contains(&Ecosystem::JavaScript) {
        match run_knip(project_path, timeout_secs) {
            Ok(f) => findings.extend(f),
            Err(e) => {
                // knip failure is not a BLOCK - it's optional
                eprintln!("  {} knip failed: {}", "!".yellow(), e);
            }
        }
    }

    findings
}

/// Truncate output to a maximum length to avoid flooding the terminal.
fn truncate_output(output: &str, max_chars: usize) -> String {
    if output.len() <= max_chars {
        output.to_string()
    } else {
        let truncated = &output[..max_chars];
        format!(
            "{}...\n[truncated - {} chars total]",
            truncated,
            output.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_output() {
        let output = "short";
        assert_eq!(truncate_output(output, 100), "short");
    }

    #[test]
    fn test_truncate_long_output() {
        let output = "a".repeat(500);
        let result = truncate_output(&output, 100);
        assert!(result.contains("[truncated"));
        assert!(result.contains("500 chars total"));
    }

    #[test]
    fn test_truncate_exact_length() {
        let output = "a".repeat(100);
        assert_eq!(truncate_output(&output, 100), output);
    }
}
