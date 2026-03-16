use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// The ai-rsk configuration file, loaded from ai-rsk.config.yaml at the project root.
/// If no config file exists, all defaults apply (strict = all rules active, no exclusions).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Additional paths to exclude from scanning (beyond the built-in exclusions).
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Maximum number of ai-rsk-ignore comments allowed in the codebase.
    /// If exceeded, ai-rsk produces a BLOCK finding.
    /// None = no limit (project maintainer decides).
    #[serde(default)]
    pub max_ignores: Option<usize>,

    /// Timeout in seconds for each external tool execution.
    /// If a tool exceeds this, it is killed and a BLOCK is generated.
    /// Default: 120 seconds.
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_seconds: u64,

    /// Minimum required versions for external tools.
    /// Key = tool name (e.g., "semgrep"), value = minimum version string.
    #[serde(default)]
    pub min_versions: HashMap<String, String>,

    /// Rules to disable, with mandatory justification.
    #[serde(default)]
    pub disabled_rules: Vec<DisabledRule>,

    /// Active compliance profiles. Default: ["security"].
    /// Available: "security", "gdpr", "ai-act", "seo", "a11y".
    /// Rules with a category not in this list are skipped.
    #[serde(default = "default_profiles")]
    pub profiles: Vec<String>,

    /// Environment mode. Filters rules that have a mode constraint.
    /// Values: "development", "production". None = no filtering (all rules active).
    #[serde(default)]
    pub mode: Option<String>,

    /// Region hint. "eu" automatically activates the "gdpr" profile.
    #[serde(default)]
    pub region: Option<String>,

    /// Semgrep rules to exclude from scanning.
    /// Use this to suppress known false positives from Semgrep's community rules.
    /// Example: ["html.security.audit.missing-integrity.missing-integrity"]
    #[serde(default)]
    pub semgrep_exclude_rules: Vec<String>,
}

/// A rule disabled in the config, with mandatory justification.
#[derive(Debug, Deserialize)]
pub struct DisabledRule {
    pub id: String,
    /// Why this rule is disabled - mandatory, ai-rsk refuses empty reasons.
    pub reason: String,
}

fn default_tool_timeout() -> u64 {
    120
}

fn default_profiles() -> Vec<String> {
    vec!["security".to_string()]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exclude: Vec::new(),
            max_ignores: None,
            tool_timeout_seconds: default_tool_timeout(),
            min_versions: HashMap::new(),
            disabled_rules: Vec::new(),
            profiles: default_profiles(),
            mode: None,
            region: None,
            semgrep_exclude_rules: Vec::new(),
        }
    }
}

impl Config {
    /// Resolve the effective list of active profiles, merging config + CLI overrides.
    /// - "security" is always included.
    /// - region: "eu" adds "gdpr" automatically.
    /// - CLI flags (gdpr, seo, a11y, ai_act) add their respective profiles.
    /// - CLI flag "all" activates every profile.
    pub fn resolve_profiles(
        &self,
        cli_gdpr: bool,
        cli_seo: bool,
        cli_a11y: bool,
        cli_ai_act: bool,
        cli_all: bool,
    ) -> Vec<String> {
        if cli_all {
            return vec![
                "security".to_string(),
                "gdpr".to_string(),
                "ai-act".to_string(),
                "seo".to_string(),
                "a11y".to_string(),
            ];
        }

        let mut profiles: Vec<String> = self.profiles.clone();

        // Ensure "security" is always present
        if !profiles.iter().any(|p| p == "security") {
            profiles.insert(0, "security".to_string());
        }

        // region: "eu" implies gdpr
        if let Some(ref region) = self.region {
            if region.eq_ignore_ascii_case("eu") && !profiles.iter().any(|p| p == "gdpr") {
                profiles.push("gdpr".to_string());
            }
        }

        // CLI flags override
        if cli_gdpr && !profiles.iter().any(|p| p == "gdpr") {
            profiles.push("gdpr".to_string());
        }
        if cli_seo && !profiles.iter().any(|p| p == "seo") {
            profiles.push("seo".to_string());
        }
        if cli_a11y && !profiles.iter().any(|p| p == "a11y") {
            profiles.push("a11y".to_string());
        }
        if cli_ai_act && !profiles.iter().any(|p| p == "ai-act") {
            profiles.push("ai-act".to_string());
        }

        profiles
    }

    /// Resolve the effective mode, with CLI override taking precedence over config.
    pub fn resolve_mode(&self, cli_mode: &Option<String>) -> Option<String> {
        cli_mode.clone().or_else(|| self.mode.clone())
    }
}

impl Config {
    /// Load config from a project path. Looks for ai-rsk.config.yaml at the root.
    /// Returns default config if the file doesn't exist.
    pub fn load(project_path: &Path) -> Result<Self> {
        let config_path = project_path.join("ai-rsk.config.yaml");

        if !config_path.exists() {
            // Also check .yml extension
            let alt_path = project_path.join("ai-rsk.config.yml");
            if !alt_path.exists() {
                return Ok(Self::default());
            }
            return Self::load_from_file(&alt_path);
        }

        Self::load_from_file(&config_path)
    }

    fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        // Validate: disabled rules must have non-empty reasons
        for rule in &config.disabled_rules {
            if rule.reason.trim().is_empty() {
                anyhow::bail!(
                    "Disabled rule '{}' in {} has no justification. Each disabled rule MUST have a 'reason' explaining why.",
                    rule.id,
                    path.display()
                );
            }
        }

        Ok(config)
    }

    /// Check if a rule ID is disabled in the config.
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.iter().any(|r| r.id == rule_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.exclude.is_empty());
        assert!(config.max_ignores.is_none());
        assert_eq!(config.tool_timeout_seconds, 120);
        assert!(config.min_versions.is_empty());
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn test_load_no_file() {
        let dir = TempDir::new().expect("create temp dir");
        let config = Config::load(dir.path()).expect("load default");
        assert_eq!(config.tool_timeout_seconds, 120);
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn test_load_full_config() {
        let dir = TempDir::new().expect("create temp dir");
        let yaml = r#"
exclude:
  - "generated/"
  - "migrations/"
max_ignores: 5
tool_timeout_seconds: 60
min_versions:
  semgrep: "1.50.0"
  gitleaks: "8.18.0"
disabled_rules:
  - id: MISSING_CSP
    reason: "CSP is handled by Cloudflare, not in app code"
  - id: MISSING_HSTS
    reason: "HSTS is set at the reverse proxy level (Traefik)"
"#;
        fs::write(dir.path().join("ai-rsk.config.yaml"), yaml).expect("write config");

        let config = Config::load(dir.path()).expect("load config");
        assert_eq!(config.exclude, vec!["generated/", "migrations/"]);
        assert_eq!(config.max_ignores, Some(5));
        assert_eq!(config.tool_timeout_seconds, 60);
        assert_eq!(config.min_versions.get("semgrep").unwrap(), "1.50.0");
        assert_eq!(config.disabled_rules.len(), 2);
        assert!(config.is_rule_disabled("MISSING_CSP"));
        assert!(!config.is_rule_disabled("TOKEN_IN_LOCALSTORAGE"));
    }

    #[test]
    fn test_load_yml_extension() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("ai-rsk.config.yml"),
            "tool_timeout_seconds: 30",
        )
        .expect("write config");

        let config = Config::load(dir.path()).expect("load config");
        assert_eq!(config.tool_timeout_seconds, 30);
    }

    #[test]
    fn test_disabled_rule_empty_reason_rejected() {
        let dir = TempDir::new().expect("create temp dir");
        let yaml = r#"
disabled_rules:
  - id: MISSING_CSP
    reason: ""
"#;
        fs::write(dir.path().join("ai-rsk.config.yaml"), yaml).expect("write config");

        let result = Config::load(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no justification"));
    }

    #[test]
    fn test_disabled_rule_whitespace_reason_rejected() {
        let dir = TempDir::new().expect("create temp dir");
        let yaml = r#"
disabled_rules:
  - id: MISSING_CSP
    reason: "   "
"#;
        fs::write(dir.path().join("ai-rsk.config.yaml"), yaml).expect("write config");

        let result = Config::load(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_field_rejected() {
        let dir = TempDir::new().expect("create temp dir");
        let yaml = "unknown_field: true";
        fs::write(dir.path().join("ai-rsk.config.yaml"), yaml).expect("write config");

        let result = Config::load(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_max_ignores_none_by_default() {
        let dir = TempDir::new().expect("create temp dir");
        fs::write(
            dir.path().join("ai-rsk.config.yaml"),
            "tool_timeout_seconds: 90",
        )
        .expect("write config");

        let config = Config::load(dir.path()).expect("load config");
        assert!(config.max_ignores.is_none());
    }
}
