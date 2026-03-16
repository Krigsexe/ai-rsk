use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ai-rsk",
    version,
    about = "AI Rust Security Keeper - all-in-one LLM security gate",
    long_about = "Blocks the build until security flaws are fixed, forces external tool installation, \
                  analyzes project stack, and enforces LLM discipline."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan the project for security issues, missing tools, and technical debt
    Scan {
        /// Path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Promote WARN to BLOCK (defense-in-depth enforcement)
        #[arg(long)]
        strict: bool,

        /// Promote WARN and ADVISE to BLOCK (full enforcement - LLM cannot ignore anything)
        #[arg(long)]
        full: bool,

        /// Output results as JSON (for CI/CD integration and programmatic consumption)
        #[arg(long)]
        json: bool,

        /// Enable GDPR/RGPD compliance checks (cookies, consent, privacy)
        #[arg(long)]
        gdpr: bool,

        /// Enable SEO checks (robots.txt, meta tags, sitemap)
        #[arg(long)]
        seo: bool,

        /// Enable accessibility checks (WCAG 2.2, alt text, lang)
        #[arg(long)]
        a11y: bool,

        /// Enable EU AI Act compliance checks (labeling, transparency)
        #[arg(long)]
        ai_act: bool,

        /// Enable ALL compliance profiles (security + gdpr + ai-act + seo + a11y)
        #[arg(long)]
        all: bool,

        /// Environment mode: development or production (filters mode-specific rules)
        #[arg(long)]
        mode: Option<String>,
    },

    /// Initialize ai-rsk in the current project (generate config, hooks, LLM rules)
    Init {
        /// Path to initialize (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Check which external tools are installed and their versions
    Check {
        /// Path to check ecosystem detection (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn test_scan_default_path() {
        let cli = Cli::try_parse_from(["ai-rsk", "scan"]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
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
                    assert_eq!(path, PathBuf::from("."));
                    assert!(!strict);
                    assert!(!full);
                    assert!(!json);
                    assert!(!gdpr);
                    assert!(!seo);
                    assert!(!a11y);
                    assert!(!ai_act);
                    assert!(!all);
                    assert!(mode.is_none());
                }
                _ => panic!("Expected Scan command"),
            }
        }
    }

    #[test]
    fn test_scan_with_strict() {
        let cli = Cli::try_parse_from(["ai-rsk", "scan", "--strict"]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            match cli.command {
                Commands::Scan { strict, .. } => assert!(strict),
                _ => panic!("Expected Scan command"),
            }
        }
    }

    #[test]
    fn test_scan_with_full() {
        let cli = Cli::try_parse_from(["ai-rsk", "scan", "--full"]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            match cli.command {
                Commands::Scan { full, .. } => assert!(full),
                _ => panic!("Expected Scan command"),
            }
        }
    }

    #[test]
    fn test_scan_with_json() {
        let cli = Cli::try_parse_from(["ai-rsk", "scan", "--json"]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            match cli.command {
                Commands::Scan { json, .. } => assert!(json),
                _ => panic!("Expected Scan command"),
            }
        }
    }

    #[test]
    fn test_scan_with_custom_path() {
        let cli = Cli::try_parse_from(["ai-rsk", "scan", "/tmp/myproject"]);
        assert!(cli.is_ok());
        if let Ok(cli) = cli {
            match cli.command {
                Commands::Scan { path, .. } => {
                    assert_eq!(path, PathBuf::from("/tmp/myproject"));
                }
                _ => panic!("Expected Scan command"),
            }
        }
    }

    #[test]
    fn test_init_command() {
        let cli = Cli::try_parse_from(["ai-rsk", "init"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_check_command() {
        let cli = Cli::try_parse_from(["ai-rsk", "check"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_unknown_command_fails() {
        let cli = Cli::try_parse_from(["ai-rsk", "nonexistent"]);
        assert!(cli.is_err());
        if let Err(e) = cli {
            assert!(!matches!(
                e.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ));
        }
    }

    #[test]
    fn test_help_is_display_help() {
        let cli = Cli::try_parse_from(["ai-rsk", "--help"]);
        assert!(cli.is_err());
        if let Err(e) = cli {
            assert_eq!(e.kind(), ErrorKind::DisplayHelp);
        }
    }

    #[test]
    fn test_version_is_display_version() {
        let cli = Cli::try_parse_from(["ai-rsk", "--version"]);
        assert!(cli.is_err());
        if let Err(e) = cli {
            assert_eq!(e.kind(), ErrorKind::DisplayVersion);
        }
    }
}
