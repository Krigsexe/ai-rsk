mod analyze;
mod ast_filter;
mod cli;
mod config;
mod detect;
mod embedded_rules;
mod init;
mod rules;
mod runner;
mod tools;
mod types;
mod version;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {}", "[ERROR]".red().bold(), e);
        process::exit(2);
    }
}

fn run() -> Result<()> {
    // Default command: `ai-rsk` without arguments = `ai-rsk scan`
    // If parsing fails (no subcommand given), inject "scan" and retry.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // DisplayHelp with no subcommand = user typed just `ai-rsk`
            // DisplayHelp from --help / DisplayVersion from --version = let clap handle it
            if e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                || e.kind() == clap::error::ErrorKind::MissingSubcommand
            {
                // Check if user explicitly asked for help (--help / -h)
                let raw_args: Vec<String> = std::env::args().collect();
                let has_help = raw_args.iter().any(|a| a == "--help" || a == "-h");
                if has_help {
                    e.exit();
                }
                let mut args = raw_args;
                args.insert(1, "scan".to_string());
                Cli::parse_from(args)
            } else {
                e.exit();
            }
        }
    };

    match cli.command {
        Commands::Scan {
            path,
            strict,
            full,
            json,
            gdpr,
            seo,
            a11y,
            ai_act,
            all,
            mode,
        } => {
            let path = path.canonicalize().unwrap_or(path);

            // Step 0: Check for updates (non-blocking, silent on failure)
            if !json {
                version::check_for_update();
            }

            // Step 0.5: LOAD config
            let config = config::Config::load(&path)?;

            // Resolve active profiles and mode from config + CLI flags
            let active_profiles = config.resolve_profiles(gdpr, seo, a11y, ai_act, all);
            let active_mode = config.resolve_mode(&mode);

            // Step 1: DETECT ecosystems
            let ecosystems = detect::detect_ecosystems(&path);
            if !json {
                println!(
                    "{}\n",
                    format!(
                        "ai-rsk v{} - Security Gate + Project Analysis",
                        env!("CARGO_PKG_VERSION")
                    )
                    .bold()
                );
                println!(
                    "{}",
                    "===================================================".dimmed()
                );

                // Show config info if non-default
                if !config.disabled_rules.is_empty() {
                    println!("  Config: {} rules disabled", config.disabled_rules.len());
                }
                if !config.exclude.is_empty() {
                    println!("  Config: {} extra exclusions", config.exclude.len());
                }

                // Show active profiles if non-default
                if active_profiles.len() > 1 || active_profiles.iter().any(|p| p != "security") {
                    println!("  Profiles: {}", active_profiles.join(", ").cyan());
                }
                if let Some(ref m) = active_mode {
                    println!("  Mode: {}", m.cyan());
                }

                if ecosystems.is_empty() {
                    println!(
                        "  {}",
                        "No known ecosystem detected. Running universal tools only.".yellow()
                    );
                } else {
                    print!("  Ecosystems: ");
                    let names: Vec<String> = ecosystems.iter().map(|e| format!("{e}")).collect();
                    println!("{}", names.join(", ").cyan());
                }
            }

            // Step 2: CHECK tool presence
            let mut result = types::ScanResult::new();
            result.ecosystems = ecosystems.clone();

            let required = tools::get_required_tools(&ecosystems);
            for tool in &required {
                let mut status = tools::check_tool(tool);

                match &status {
                    types::ToolStatus::Missing => {
                        // Auto-install: try to install the tool automatically
                        if tools::auto_install_tool(tool) {
                            // Re-check after installation
                            status = tools::check_tool(tool);
                        }

                        // If still missing after auto-install attempt, BLOCK
                        if matches!(status, types::ToolStatus::Missing) {
                            result.findings.push(types::Finding {
                                severity: types::Severity::Block,
                                kind: types::FindingKind::ToolMissing {
                                    tool_name: tool.name.clone(),
                                    install_hint: tool.install_hint.clone(),
                                },
                                file: None,
                                line: None,
                                message: format!(
                                    "{} is required but not found in PATH. Auto-install failed.",
                                    tool.name
                                ),
                            });
                        } else if let types::ToolStatus::Installed { ref version } = status
                            && !json
                        {
                            println!(
                                "  {} {} {} {}",
                                "✓".green(),
                                tool.name,
                                version.dimmed(),
                                "(auto-installed)".cyan()
                            );
                        }
                    }
                    types::ToolStatus::Installed { .. } => {
                        // Auto-update: ensure the tool is at its latest version
                        tools::auto_update_tool(tool);
                        // Re-check version after update
                        status = tools::check_tool(tool);
                        if let types::ToolStatus::Installed { ref version } = status
                            && !json
                        {
                            println!("  {} {} {}", "✓".green(), tool.name, version.dimmed());
                        }
                    }
                }
                result.tool_statuses.push((tool.name.clone(), status));
            }

            // Check minimum versions from config
            if !config.min_versions.is_empty() {
                for (tool_name, status) in &result.tool_statuses {
                    if let types::ToolStatus::Installed { version } = status
                        && let Some(min_version) = config.min_versions.get(tool_name)
                        && !tools::version_satisfies(version, min_version)
                    {
                        result.findings.push(types::Finding {
                            severity: types::Severity::Block,
                            kind: types::FindingKind::ToolMissing {
                                tool_name: tool_name.clone(),
                                install_hint: format!(
                                    "Current version: {}. Minimum required: {}. Update the tool.",
                                    version, min_version
                                ),
                            },
                            file: None,
                            line: None,
                            message: format!(
                                "{} version {} is below minimum required {}.",
                                tool_name, version, min_version
                            ),
                        });
                    }
                }
            }

            // Check recommended tools
            let recommended = tools::get_recommended_tools(&ecosystems);
            for tool in &recommended {
                let status = tools::check_tool(tool);
                if let types::ToolStatus::Missing = &status {
                    result.findings.push(types::Finding {
                        severity: types::Severity::Advise,
                        kind: types::FindingKind::ProjectAdvice {
                            advice_id: format!("MISSING_RECOMMENDED_{}", tool.name.to_uppercase()),
                            question: format!(
                                "Consider installing {} for {}. Install: {}",
                                tool.name,
                                match tool.name.as_str() {
                                    "rtk" => "60-90% token savings on LLM operations",
                                    "knip" => "dead code and unused dependency detection",
                                    "cargo-audit" => "Rust dependency vulnerability auditing",
                                    _ => "enhanced project analysis",
                                },
                                tool.install_hint
                            ),
                        },
                        file: None,
                        line: None,
                        message: format!("{} is recommended but not installed.", tool.name),
                    });
                } else if let types::ToolStatus::Installed { version } = &status
                    && !json
                {
                    println!(
                        "  {} {} {} {}",
                        "✓".green(),
                        tool.name,
                        version.dimmed(),
                        "(recommended)".dimmed()
                    );
                }
                result.tool_statuses.push((tool.name.clone(), status));
            }

            if !json {
                println!(
                    "{}",
                    "===================================================".dimmed()
                );
            }

            // Step 3: RUN external tools (only if all required tools are installed)
            let has_missing_tools = result
                .findings
                .iter()
                .any(|f| matches!(f.kind, types::FindingKind::ToolMissing { .. }));

            if has_missing_tools {
                if !json {
                    println!(
                        "\n  {}",
                        "Skipping tool execution - install missing tools first.".yellow()
                    );
                }
            } else {
                if !json {
                    print!("\n  {} ", "[1/3]".cyan());
                    println!("Running external tools...");
                }
                let tool_findings = runner::run_external_tools(
                    &path,
                    &ecosystems,
                    config.tool_timeout_seconds,
                    &config.semgrep_exclude_rules,
                );
                result.findings.extend(tool_findings);
            }

            // Step 4: SCAN couche 1 (internal YAML rules)
            let rules_dir = rules::find_rules_dir(&path);
            match rules::load_rules(&rules_dir) {
                Ok(loaded_rules) => {
                    // Filter rules: disabled by config, category not in active profiles, mode mismatch
                    let active_rules: Vec<_> = loaded_rules
                        .into_iter()
                        .filter(|r| !config.is_rule_disabled(&r.id))
                        .filter(|r| active_profiles.iter().any(|p| p == &r.category))
                        .filter(|r| match &r.mode {
                            None => true, // No mode constraint = always active
                            Some(rule_mode) => match &active_mode {
                                None => true, // No active mode set = all rules active
                                Some(am) => rule_mode == am,
                            },
                        })
                        .collect();

                    let disabled_count = config.disabled_rules.len();
                    if active_rules.is_empty() {
                        if !json {
                            println!("  {}", "No rules found - skipping couche 1 scan.".yellow());
                        }
                    } else {
                        if !json {
                            if disabled_count > 0 {
                                println!(
                                    "  {} Scanning {} rules ({} disabled by config)",
                                    "[2/3]".cyan(),
                                    active_rules.len(),
                                    disabled_count
                                );
                            } else {
                                println!("  {} Scanning {} rules...", "[2/3]".cyan(), active_rules.len());
                            }
                        }
                        match rules::scan_files(&path, &active_rules, &config.exclude) {
                            Ok((rule_findings, ignores)) => {
                                result.findings.extend(rule_findings);
                                result.ignore_count += ignores;
                            }
                            Err(e) => {
                                eprintln!("  {} Couche 1 scan error: {}", "!".red(), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  {} Failed to load rules: {}", "!".red(), e);
                }
            }

            // Check max_ignores threshold
            if let Some(max) = config.max_ignores
                && result.ignore_count > max
            {
                result.findings.push(types::Finding {
                        severity: types::Severity::Block,
                        kind: types::FindingKind::ProjectAdvice {
                            advice_id: "TOO_MANY_IGNORES".to_string(),
                            question: format!(
                                "{} ai-rsk-ignore comments found (max allowed: {}). Review your codebase - too many ignores defeat the purpose of security scanning.",
                                result.ignore_count,
                                max
                            ),
                        },
                        file: None,
                        line: None,
                        message: format!(
                            "Too many ai-rsk-ignore comments: {} found, {} allowed.",
                            result.ignore_count,
                            max
                        ),
                    });
            }

            // Step 5: ANALYZE project structure (couche 3 - ADVISE)
            if !json {
                print!("\n  {} ", "[3/3]".cyan());
                println!("Analyzing project structure...");
            }
            let analysis_findings = analyze::analyze_project(&path, &ecosystems, &active_profiles);
            let analysis_count = analysis_findings.len();
            result.findings.extend(analysis_findings);
            if !json {
                if analysis_count > 0 {
                    println!("  Couche 3: {} advisory findings", analysis_count);
                } else {
                    println!("  {}", "Couche 3: project structure looks good.".green());
                }

                println!(
                    "{}",
                    "===================================================".dimmed()
                );
            }

            // Step 6+7: COLLECT, sort by severity, REPORT
            result.findings.sort_by(|a, b| b.severity.cmp(&a.severity));

            let blocks = result.count_by_severity(types::Severity::Block);
            let warns = result.count_by_severity(types::Severity::Warn);
            let advises = result.count_by_severity(types::Severity::Advise);
            let score = result.security_score();
            let exit = result.exit_code(strict, full);

            // Write persistent report to .ai-rsk/report.md
            // The LLM is obligated to read this file before coding.
            if let Err(e) = result.write_report(&path, strict, full) {
                eprintln!(
                    "WARNING: Could not write report to .ai-rsk/report.md: {}",
                    e
                );
            } else if !json {
                println!(
                    "\n  {} {}",
                    "→".cyan(),
                    "Report written to .ai-rsk/report.md — READ THIS FILE BEFORE CODING".bold()
                );
            }

            if json {
                // JSON output for CI/CD integration
                let mode = if full {
                    "--full"
                } else if strict {
                    "--strict"
                } else {
                    "default"
                };
                let output = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "result": if exit == 0 { "PASS" } else { "BLOCKED" },
                    "exit_code": exit,
                    "mode": mode,
                    "security_score": score,
                    "summary": {
                        "block": blocks,
                        "warn": warns,
                        "advise": advises,
                        "ignores": result.ignore_count,
                    },
                    "findings": result.findings,
                    "ecosystems": result.ecosystems,
                    "tool_statuses": result.tool_statuses,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).expect("JSON serialization failed")
                );
            } else {
                // Terminal output with colors
                for finding in &result.findings {
                    let label = match finding.severity {
                        types::Severity::Block => format!("[{}]", "BLOCK".red().bold()),
                        types::Severity::Warn => format!("[{}]", "WARN".yellow().bold()),
                        types::Severity::Advise => format!("[{}]", "ADVISE".blue().bold()),
                    };

                    println!("\n{} {}", label, finding.message);

                    if let Some(ref file) = finding.file {
                        let loc = match finding.line {
                            Some(line) => format!("{}:{}", file.display(), line),
                            None => format!("{}", file.display()),
                        };
                        println!("  File: {}", loc);
                    }

                    match &finding.kind {
                        types::FindingKind::ToolMissing { install_hint, .. } => {
                            println!("  Fix: {}", install_hint);
                        }
                        types::FindingKind::RuleViolation {
                            rule_id,
                            cwe,
                            code_snippet,
                            fix,
                            ..
                        } => {
                            if !cwe.is_empty() {
                                let cwe_links: Vec<String> = cwe
                                    .iter()
                                    .map(|c| {
                                        let id = c.strip_prefix("CWE-").unwrap_or(c);
                                        format!(
                                            "{} (https://cwe.mitre.org/data/definitions/{}.html)",
                                            c, id
                                        )
                                    })
                                    .collect();
                                println!("  Rule: {}", rule_id);
                                for link in &cwe_links {
                                    println!("  Ref:  {}", link.dimmed());
                                }
                            } else {
                                println!("  Rule: {}", rule_id);
                            }
                            if !code_snippet.is_empty() {
                                println!("  Code: {}", code_snippet);
                            }
                            if !fix.is_empty() {
                                println!("  Fix:  {}", fix);
                            }
                        }
                        types::FindingKind::ProjectAdvice { question, .. } => {
                            println!("  {}", question);
                        }
                        types::FindingKind::ToolFailed { output, .. } => {
                            for line in output.lines().take(10) {
                                println!("  {}", line);
                            }
                        }
                    }
                }

                println!(
                    "\n{}",
                    "===================================================".dimmed()
                );
                // Security score with color based on value
                let score_colored = if score >= 80 {
                    format!("{}/100", score).green().bold()
                } else if score >= 50 {
                    format!("{}/100", score).yellow().bold()
                } else {
                    format!("{}/100", score).red().bold()
                };
                println!("Security Score: {}", score_colored);

                if exit == 0 {
                    println!(
                        "Result: {} ({}B {}W {}A)",
                        "PASS".green().bold(),
                        blocks,
                        warns,
                        advises
                    );
                } else {
                    println!(
                        "Result: {} ({}B {}W {}A)",
                        "BLOCKED".red().bold(),
                        blocks,
                        warns,
                        advises
                    );
                }
                if result.ignore_count > 0 {
                    println!("Ignores: {}", result.ignore_count);
                }
                let mode = if full {
                    "--full"
                } else if strict {
                    "--strict"
                } else {
                    "default"
                };
                println!("Mode: {}", mode);
                println!("Exit code: {}", exit);
                println!(
                    "{}",
                    "===================================================".dimmed()
                );

                // Guidance: tell the user what to do next
                if blocks > 0 {
                    println!(
                        "\n  {} Fix the {} {} first - the build is blocked until they are resolved.",
                        "Next:".bold(),
                        blocks,
                        if blocks == 1 { "BLOCK finding" } else { "BLOCK findings" }
                    );
                    if warns > 0 {
                        println!(
                            "  Then address the {} {} (they become BLOCK with --strict).",
                            warns,
                            if warns == 1 { "WARN" } else { "WARNs" }
                        );
                    }
                    println!(
                        "  After fixing, run {} to verify.",
                        "ai-rsk scan".cyan()
                    );
                } else if warns > 0 && strict {
                    println!(
                        "\n  {} Fix the {} {} - strict mode is active.",
                        "Next:".bold(),
                        warns,
                        if warns == 1 { "WARN finding" } else { "WARN findings" }
                    );
                } else if exit == 0 {
                    println!(
                        "\n  {} All clear. Report saved to {}",
                        "✓".green(),
                        ".ai-rsk/report.md".bold()
                    );
                }
            }

            process::exit(exit);
        }

        Commands::Init { path } => {
            let path = path.canonicalize().unwrap_or(path);
            init::run_init(&path)?;
        }

        Commands::Update => {
            version::run_self_update();
        }

        Commands::Check { path } => {
            let path = path.canonicalize().unwrap_or(path);
            let ecosystems = detect::detect_ecosystems(&path);
            println!("Ecosystems detected: {:?}", ecosystems);

            let required = tools::get_required_tools(&ecosystems);
            let recommended = tools::get_recommended_tools(&ecosystems);

            for tool in required.iter().chain(recommended.iter()) {
                let status = tools::check_tool(tool);
                let req_label = if tool.required {
                    "required"
                } else {
                    "recommended"
                };
                match status {
                    types::ToolStatus::Installed { version } => {
                        println!(
                            "  {} {} {} ({})",
                            "✓".green(),
                            tool.name,
                            version,
                            req_label
                        );
                    }
                    types::ToolStatus::Missing => {
                        println!(
                            "  {} {} - NOT FOUND ({}) - {}",
                            "✗".red(),
                            tool.name,
                            req_label,
                            tool.install_hint
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
