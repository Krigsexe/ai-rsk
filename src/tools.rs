use crate::types::{Ecosystem, ExternalTool, ToolStatus};
use colored::Colorize;
use std::path::PathBuf;
use std::process::Command;

/// Get the list of required tools based on detected ecosystems.
/// These 3 are ALWAYS required regardless of ecosystem.
/// Ecosystem-specific tools are added on top.
pub fn get_required_tools(ecosystems: &[Ecosystem]) -> Vec<ExternalTool> {
    let mut tools = vec![
        ExternalTool {
            name: "semgrep".to_string(),
            binary: "semgrep".to_string(),
            required: true,
            install_hint: "pipx install semgrep  OR  pip install semgrep  OR  brew install semgrep".to_string(),
            install_commands: vec![
                vec!["pipx".into(), "install".into(), "semgrep".into()],
                vec!["pip".into(), "install".into(), "--user".into(), "semgrep".into()],
                vec!["pip".into(), "install".into(), "--system".into(), "semgrep".into()],
                vec!["pip3".into(), "install".into(), "--user".into(), "semgrep".into()],
                vec!["brew".into(), "install".into(), "semgrep".into()],
            ],
            update_commands: vec![
                vec!["pipx".into(), "upgrade".into(), "semgrep".into()],
                vec!["pip".into(), "install".into(), "--upgrade".into(), "semgrep".into()],
                vec!["pip3".into(), "install".into(), "--upgrade".into(), "semgrep".into()],
                vec!["brew".into(), "upgrade".into(), "semgrep".into()],
            ],
            github_release: None, // Semgrep is Python-based, no single binary release
        },
        ExternalTool {
            name: "gitleaks".to_string(),
            binary: "gitleaks".to_string(),
            required: true,
            install_hint: "brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest".to_string(),
            install_commands: vec![
                vec!["brew".into(), "install".into(), "gitleaks".into()],
                vec!["go".into(), "install".into(), "github.com/gitleaks/gitleaks/v8@latest".into()],
            ],
            update_commands: vec![
                vec!["brew".into(), "upgrade".into(), "gitleaks".into()],
                vec!["go".into(), "install".into(), "github.com/gitleaks/gitleaks/v8@latest".into()],
            ],
            github_release: Some((
                "gitleaks/gitleaks".into(),
                "gitleaks_{version}_{os}_{arch}.tar.gz".into(),
            )),
        },
        ExternalTool {
            name: "osv-scanner".to_string(),
            binary: "osv-scanner".to_string(),
            required: true,
            install_hint: "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest  OR  brew install osv-scanner".to_string(),
            install_commands: vec![
                vec!["go".into(), "install".into(), "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest".into()],
                vec!["brew".into(), "install".into(), "osv-scanner".into()],
            ],
            update_commands: vec![
                vec!["go".into(), "install".into(), "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest".into()],
                vec!["brew".into(), "upgrade".into(), "osv-scanner".into()],
            ],
            github_release: Some((
                "google/osv-scanner".into(),
                "osv-scanner_{os}_{arch}".into(),
            )),
        },
    ];

    // Ecosystem-specific required tools
    if ecosystems.contains(&Ecosystem::JavaScript) {
        tools.push(ExternalTool {
            name: "knip".to_string(),
            binary: "knip".to_string(),
            required: true,
            install_hint: "npm install -g knip  OR  npm install -D knip (in your project)"
                .to_string(),
            install_commands: vec![
                vec!["npm".into(), "install".into(), "-g".into(), "knip".into()],
                vec!["pnpm".into(), "add".into(), "-g".into(), "knip".into()],
                vec!["bun".into(), "add".into(), "-g".into(), "knip".into()],
            ],
            update_commands: vec![vec![
                "npm".into(),
                "update".into(),
                "-g".into(),
                "knip".into(),
            ]],
            github_release: None,
        });
    }

    tools
}

/// Get the list of recommended tools based on detected ecosystems.
/// RTK is always recommended regardless of ecosystem.
pub fn get_recommended_tools(ecosystems: &[Ecosystem]) -> Vec<ExternalTool> {
    let mut tools = vec![ExternalTool {
        name: "rtk".to_string(),
        binary: "rtk".to_string(),
        required: false,
        install_hint: "cargo install --git https://github.com/rtk-ai/rtk".to_string(),
        install_commands: vec![],
        update_commands: vec![],
        github_release: None,
    }];

    for eco in ecosystems {
        match eco {
            Ecosystem::JavaScript => {
                // knip is now required (moved to get_required_tools)
            }
            Ecosystem::Rust => {
                tools.push(ExternalTool {
                    name: "cargo-audit".to_string(),
                    binary: "cargo-audit".to_string(),
                    required: false,
                    install_hint: "cargo install cargo-audit".to_string(),
                    install_commands: vec![],
                    update_commands: vec![],
                    github_release: None,
                });
            }
            _ => {}
        }
    }

    tools
}

/// Check if a tool is installed by looking for its binary in PATH
/// and extracting its version.
pub fn check_tool(tool: &ExternalTool) -> ToolStatus {
    // First check if the binary exists in PATH
    if which::which(&tool.binary).is_err() {
        return ToolStatus::Missing;
    }

    // Try to get version
    let version = get_tool_version(&tool.binary);

    ToolStatus::Installed {
        version: version.unwrap_or_else(|| "unknown".to_string()),
    }
}

/// Extract version string from a tool by running `tool --version`.
fn get_tool_version(binary: &str) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Some tools output version to stdout, some to stderr
    let version_text = if stdout.trim().is_empty() {
        stderr.to_string()
    } else {
        stdout.to_string()
    };

    // Extract first line, trim whitespace
    let first_line = version_text.lines().next()?.trim().to_string();

    if first_line.is_empty() {
        None
    } else {
        Some(first_line)
    }
}

/// Compare two semver-like version strings.
/// Returns true if `current` >= `required`.
/// Handles formats like "1.50.0", "v1.50.0", "semgrep 1.50.0", etc.
/// Extracts the first version-like pattern (digits.digits.digits) from the string.
pub fn version_satisfies(current_version_str: &str, required: &str) -> bool {
    let extract_version = |s: &str| -> Option<Vec<u64>> {
        // Find a pattern that looks like a version number (digits.digits or digits.digits.digits)
        let re = regex::Regex::new(r"(\d+)\.(\d+)(?:\.(\d+))?").ok()?;
        let caps = re.captures(s)?;
        let major: u64 = caps.get(1)?.as_str().parse().ok()?;
        let minor: u64 = caps.get(2)?.as_str().parse().ok()?;
        let patch: u64 = caps
            .get(3)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        Some(vec![major, minor, patch])
    };

    let current = match extract_version(current_version_str) {
        Some(v) => v,
        None => return false, // Can't parse current → assume not satisfying
    };
    let required = match extract_version(required) {
        Some(v) => v,
        None => return true, // Can't parse required → no constraint
    };

    current >= required
}

/// RAII guard that removes a temporary directory when dropped.
struct TmpDirGuard<'a>(&'a std::path::Path);
impl Drop for TmpDirGuard<'_> {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.0).ok();
    }
}

/// Detect the current OS as used in GitHub release asset names.
/// Returns None if the OS is not supported for binary downloads.
fn detect_os() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("linux")
    } else if cfg!(target_os = "macos") {
        Some("darwin")
    } else if cfg!(target_os = "windows") {
        Some("windows")
    } else {
        None
    }
}

/// Detect the current CPU architecture as used in GitHub release asset names.
/// Returns a tuple: (primary name, alternative name) because some projects
/// use "x64" (gitleaks) while others use "amd64" (osv-scanner).
fn detect_arch() -> Option<(&'static str, &'static str)> {
    if cfg!(target_arch = "x86_64") {
        Some(("amd64", "x64"))
    } else if cfg!(target_arch = "aarch64") {
        Some(("arm64", "arm64"))
    } else {
        None
    }
}

/// Get the user's home directory, cross-platform.
/// Linux/macOS: $HOME
/// Windows: %USERPROFILE% (fallback: %HOMEDRIVE%%HOMEPATH%)
fn home_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return Some(PathBuf::from(profile));
    }
    if let (Ok(drive), Ok(path)) = (std::env::var("HOMEDRIVE"), std::env::var("HOMEPATH")) {
        return Some(PathBuf::from(format!("{}{}", drive, path)));
    }
    None
}

/// Ensure the user-local binary directory exists and return its path.
/// Linux/macOS: ~/.local/bin/
/// Windows: %LOCALAPPDATA%\ai-rsk\bin\
fn ensure_local_bin() -> Option<PathBuf> {
    let local_bin = if cfg!(target_os = "windows") {
        let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
        PathBuf::from(local_app_data).join("ai-rsk").join("bin")
    } else {
        let home = home_dir()?;
        home.join(".local").join("bin")
    };
    if !local_bin.exists() {
        std::fs::create_dir_all(&local_bin).ok()?;
    }
    Some(local_bin)
}

/// Download and install a tool from its GitHub Releases page.
/// This is the last-resort fallback when no package manager is available.
///
/// Strategy:
/// 1. Query GitHub API for latest release tag
/// 2. Build the asset URL from the pattern in ExternalTool.github_release
/// 3. Download with curl
/// 4. Extract if archive (tar.gz), or chmod +x if bare binary
/// 5. Move to ~/.local/bin/
/// 6. Verify the tool is now callable
///
/// Requires: curl in PATH (available on Linux, macOS, and Windows 10+).
fn install_from_github_release(tool: &ExternalTool) -> bool {
    let (repo, asset_pattern) = match &tool.github_release {
        Some(r) => r,
        None => return false,
    };

    // curl is required for download.
    // On Windows 10+, curl.exe is bundled at C:\Windows\System32\curl.exe.
    // On older Windows, this will fail gracefully.
    if which::which("curl").is_err() {
        eprintln!(
            "  {} curl not found - cannot download from GitHub Releases.",
            "✗".red()
        );
        if cfg!(target_os = "windows") {
            eprintln!(
                "  {} curl.exe is included in Windows 10 1803+. If you're on an older version, install curl manually.",
                "→".cyan()
            );
        }
        return false;
    }

    let os = match detect_os() {
        Some(o) => o,
        None => {
            eprintln!(
                "  {} Unsupported OS for GitHub Release download.",
                "✗".red()
            );
            return false;
        }
    };

    let (arch_primary, arch_alt) = match detect_arch() {
        Some(a) => a,
        None => {
            eprintln!(
                "  {} Unsupported architecture for GitHub Release download.",
                "✗".red()
            );
            return false;
        }
    };

    let local_bin = match ensure_local_bin() {
        Some(p) => p,
        None => {
            eprintln!("  {} Cannot create ~/.local/bin/ directory.", "✗".red());
            return false;
        }
    };

    eprintln!(
        "  {} Downloading {} from GitHub Releases (last resort)...",
        "→".cyan(),
        tool.name.bold()
    );

    // Step 1: Get latest release tag via GitHub API
    let tag_output = Command::new("curl")
        .args([
            "-sfL",
            &format!("https://api.github.com/repos/{}/releases/latest", repo),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let tag_output = match tag_output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            eprintln!("  {} Failed to query GitHub API for {}.", "✗".red(), repo);
            return false;
        }
    };

    // Parse tag_name from the GitHub API JSON response.
    // serde_json is already a dependency of this project.
    let tag = serde_json::from_str::<serde_json::Value>(&tag_output)
        .ok()
        .and_then(|v| v["tag_name"].as_str().map(String::from));

    let tag = match tag {
        Some(t) => t,
        None => {
            eprintln!(
                "  {} Could not parse release tag from GitHub API response.",
                "✗".red()
            );
            return false;
        }
    };

    // Version without 'v' prefix (e.g., "8.30.0" from "v8.30.0")
    let version = tag.strip_prefix('v').unwrap_or(&tag);

    // Step 2: Build asset name by trying both arch variants
    // Try primary arch first (amd64), then alternative (x64)
    let asset_primary = asset_pattern
        .replace("{version}", version)
        .replace("{os}", os)
        .replace("{arch}", arch_primary);

    let asset_alt = asset_pattern
        .replace("{version}", version)
        .replace("{os}", os)
        .replace("{arch}", arch_alt);

    let is_archive = asset_primary.ends_with(".tar.gz") || asset_primary.ends_with(".zip");

    // Step 3: Download - try primary arch name first, then alternative
    // Use a unique subdirectory in the system temp dir to avoid collisions.
    // We clean it up at the end of the function.
    let tmp_dir = std::env::temp_dir().join(format!("ai-rsk-install-{}", std::process::id()));
    if std::fs::create_dir_all(&tmp_dir).is_err() {
        eprintln!("  {} Cannot create temp directory.", "✗".red());
        return false;
    }

    // Ensure cleanup on all exit paths
    let _cleanup = TmpDirGuard(&tmp_dir);

    let download_url_primary = format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, asset_primary
    );
    let download_url_alt = format!(
        "https://github.com/{}/releases/download/{}/{}",
        repo, tag, asset_alt
    );

    let mut downloaded = false;
    let mut actual_asset = asset_primary.clone();

    for (url, asset_name) in [
        (&download_url_primary, &asset_primary),
        (&download_url_alt, &asset_alt),
    ] {
        let dl_path = tmp_dir.join(asset_name);
        let status = Command::new("curl")
            .args(["-sfL", "-o", &dl_path.to_string_lossy(), url])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status();

        if let Ok(s) = status
            && s.success()
            && dl_path.exists()
            && dl_path.metadata().map(|m| m.len() > 0).unwrap_or(false)
        {
            downloaded = true;
            actual_asset = asset_name.clone();
            break;
        }
    }

    if !downloaded {
        eprintln!(
            "  {} Download failed for {} (tried both arch variants).",
            "✗".red(),
            tool.name
        );
        return false;
    }

    let actual_download_path = tmp_dir.join(&actual_asset);

    // Step 4: Extract archive or set executable bit
    let binary_path = if is_archive && actual_asset.ends_with(".tar.gz") {
        // Extract tar.gz (tar is available on Linux, macOS, and Windows 10+)
        let status = Command::new("tar")
            .args([
                "-xzf",
                &actual_download_path.to_string_lossy(),
                "-C",
                &tmp_dir.to_string_lossy(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status();

        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("  {} Failed to extract tar.gz archive.", "✗".red());
                return false;
            }
        }

        // Find the binary in the extracted files
        let extracted_binary = tmp_dir.join(&tool.binary);
        if extracted_binary.exists() {
            extracted_binary
        } else {
            eprintln!(
                "  {} Binary '{}' not found in extracted archive.",
                "✗".red(),
                tool.binary
            );
            return false;
        }
    } else if is_archive && actual_asset.ends_with(".zip") {
        // Extract .zip - common format for Windows GitHub Releases.
        // Use tar on Windows 10+ (bsdtar supports .zip) or unzip on Unix.
        let extract_status = if cfg!(target_os = "windows") {
            Command::new("tar")
                .args([
                    "-xf",
                    &actual_download_path.to_string_lossy(),
                    "-C",
                    &tmp_dir.to_string_lossy(),
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .status()
        } else {
            Command::new("unzip")
                .args([
                    "-o",
                    actual_download_path.to_string_lossy().as_ref(),
                    "-d",
                    tmp_dir.to_string_lossy().as_ref(),
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .status()
        };

        match extract_status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("  {} Failed to extract zip archive.", "✗".red());
                return false;
            }
        }

        // On Windows, the binary name has .exe extension
        let binary_name = if cfg!(target_os = "windows") {
            format!("{}.exe", tool.binary)
        } else {
            tool.binary.clone()
        };
        let extracted_binary = tmp_dir.join(&binary_name);
        if extracted_binary.exists() {
            extracted_binary
        } else {
            eprintln!(
                "  {} Binary '{}' not found in extracted zip archive.",
                "✗".red(),
                binary_name
            );
            return false;
        }
    } else {
        // Bare binary - just chmod +x
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = actual_download_path.metadata() {
                let mut perms = metadata.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&actual_download_path, perms).ok();
            }
        }
        actual_download_path
    };

    // Step 5: Move to local bin directory
    let dest_name = if cfg!(target_os = "windows") && !tool.binary.ends_with(".exe") {
        format!("{}.exe", tool.binary)
    } else {
        tool.binary.clone()
    };
    let dest = local_bin.join(&dest_name);
    if std::fs::copy(&binary_path, &dest).is_err() {
        eprintln!("  {} Failed to copy binary to {:?}.", "✗".red(), dest);
        return false;
    }

    // Ensure executable bit on final location
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = dest.metadata() {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms).ok();
        }
    }

    // Step 6: Verify - check if tool is now in PATH
    // ~/.local/bin might not be in PATH, so also check directly
    if which::which(&tool.binary).is_ok() {
        eprintln!(
            "  {} {} installed via GitHub Release ({}).",
            "✓".green(),
            tool.name,
            tag
        );
        return true;
    }

    // If not in PATH, check if the binary exists and works at dest
    let verify = Command::new(&dest)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .status();

    if let Ok(s) = verify
        && s.success()
    {
        eprintln!(
            "  {} {} installed to {} ({}). Add ~/.local/bin to your PATH if not already done.",
            "✓".green(),
            tool.name,
            dest.display(),
            tag
        );
        return true;
    }

    eprintln!(
        "  {} {} downloaded but binary verification failed.",
        "✗".red(),
        tool.name
    );
    false
}

/// Attempt to auto-install a missing tool.
/// Tries each install_command in order until one succeeds.
/// Falls back to GitHub Release download as last resort.
/// Returns true if installation succeeded (tool now in PATH), false otherwise.
pub fn auto_install_tool(tool: &ExternalTool) -> bool {
    eprintln!("  {} Auto-installing {}...", "→".cyan(), tool.name.bold());

    for cmd in &tool.install_commands {
        if cmd.is_empty() {
            continue;
        }

        let binary = &cmd[0];
        let args: Vec<&str> = cmd[1..].iter().map(|s| s.as_str()).collect();

        // Check if the installer binary exists
        if which::which(binary).is_err() {
            continue;
        }

        let result = Command::new(binary)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status();

        match result {
            Ok(status) if status.success() => {
                // Verify the tool is now in PATH
                if which::which(&tool.binary).is_ok() {
                    eprintln!("  {} {} installed successfully.", "✓".green(), tool.name);
                    return true;
                }
            }
            _ => continue,
        }
    }

    // Last resort: download from GitHub Releases
    if tool.github_release.is_some() && install_from_github_release(tool) {
        return true;
    }

    eprintln!(
        "  {} Failed to auto-install {}. Manual install required: {}",
        "✗".red(),
        tool.name,
        tool.install_hint
    );
    false
}

/// Attempt to auto-update an already installed tool to the latest version.
/// Tries each update command in order until one succeeds.
/// This handles the case where the tool was installed via different package managers
/// (e.g., semgrep via pip vs pipx vs brew).
/// Returns true if any update command ran successfully.
pub fn auto_update_tool(tool: &ExternalTool) -> bool {
    if tool.update_commands.is_empty() {
        return false;
    }

    eprintln!("  {} Updating {}...", "→".cyan(), tool.name);

    for cmd in &tool.update_commands {
        if cmd.is_empty() {
            continue;
        }

        let binary = &cmd[0];
        let args: Vec<&str> = cmd[1..].iter().map(|s| s.as_str()).collect();

        // Check if the updater binary exists
        if which::which(binary).is_err() {
            continue;
        }

        let result = Command::new(binary)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status();

        if let Ok(status) = result
            && status.success()
        {
            let new_version = get_tool_version(&tool.binary).unwrap_or_else(|| "unknown".into());
            eprintln!("  {} {} updated ({})", "✓".green(), tool.name, new_version);
            return true;
        }
    }

    // All package manager commands failed — try GitHub Release as last resort
    // This handles the case where the tool was installed via direct binary download
    if tool.github_release.is_some() && install_from_github_release(tool) {
        return true;
    }

    // All update methods failed — not a critical error, continue with current version
    eprintln!(
        "  {} {} update failed - continuing with current version.",
        "!".yellow(),
        tool.name
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_universal_tools_always_present() {
        let tools = get_required_tools(&[]);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"semgrep"));
        assert!(names.contains(&"gitleaks"));
        assert!(names.contains(&"osv-scanner"));
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn test_ecosystem_specific_required() {
        // JS/TS: 3 universal + knip = 4
        let js_tools = get_required_tools(&[Ecosystem::JavaScript]);
        assert_eq!(js_tools.len(), 4);
        assert!(js_tools.iter().any(|t| t.name == "knip"));

        // Non-JS: 3 universal only
        for eco in &[Ecosystem::Python, Ecosystem::Go, Ecosystem::Rust] {
            let tools = get_required_tools(&[*eco]);
            assert_eq!(
                tools.len(),
                3,
                "Ecosystem {:?} should have 3 required tools",
                eco
            );
        }
    }

    #[test]
    fn test_multi_ecosystem_with_js() {
        let tools = get_required_tools(&[Ecosystem::JavaScript, Ecosystem::Python, Ecosystem::Go]);
        assert_eq!(tools.len(), 4); // 3 universal + knip (JS detected)
        assert!(tools.iter().any(|t| t.name == "knip"));
    }

    #[test]
    fn test_rtk_always_recommended() {
        let tools = get_recommended_tools(&[]);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"rtk"));
    }

    #[test]
    fn test_recommended_javascript_no_knip() {
        // knip is now required, not recommended
        let tools = get_recommended_tools(&[Ecosystem::JavaScript]);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"knip"));
    }

    #[test]
    fn test_recommended_rust_has_cargo_audit() {
        let tools = get_recommended_tools(&[Ecosystem::Rust]);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"cargo-audit"));
    }

    #[test]
    fn test_all_tools_have_install_hint() {
        let required = get_required_tools(&[
            Ecosystem::JavaScript,
            Ecosystem::Python,
            Ecosystem::Go,
            Ecosystem::Rust,
        ]);
        let recommended = get_recommended_tools(&[Ecosystem::JavaScript, Ecosystem::Rust]);

        for tool in required.iter().chain(recommended.iter()) {
            assert!(
                !tool.install_hint.is_empty(),
                "Tool {} has empty install_hint",
                tool.name
            );
        }
    }

    #[test]
    fn test_version_satisfies_exact() {
        assert!(version_satisfies("1.50.0", "1.50.0"));
    }

    #[test]
    fn test_version_satisfies_newer() {
        assert!(version_satisfies("1.51.0", "1.50.0"));
        assert!(version_satisfies("2.0.0", "1.50.0"));
    }

    #[test]
    fn test_version_satisfies_older() {
        assert!(!version_satisfies("1.49.0", "1.50.0"));
        assert!(!version_satisfies("0.99.0", "1.0.0"));
    }

    #[test]
    fn test_version_satisfies_with_prefix() {
        assert!(version_satisfies("semgrep 1.50.0", "1.50.0"));
        assert!(version_satisfies("v1.50.0", "1.50.0"));
        assert!(version_satisfies("gitleaks v8.18.2", "8.18.0"));
    }

    #[test]
    fn test_version_satisfies_two_parts() {
        assert!(version_satisfies("1.50", "1.50.0"));
        assert!(version_satisfies("2.0", "1.50.0"));
    }

    #[test]
    fn test_version_satisfies_unparseable() {
        assert!(!version_satisfies("unknown", "1.50.0"));
        assert!(version_satisfies("1.50.0", "unparseable"));
    }

    #[test]
    fn test_check_nonexistent_tool() {
        let tool = ExternalTool {
            name: "nonexistent-tool-xyz".to_string(),
            binary: "nonexistent-tool-xyz".to_string(),
            required: true,
            install_hint: "impossible".to_string(),
            install_commands: vec![],
            update_commands: vec![],
            github_release: None,
        };
        assert_eq!(check_tool(&tool), ToolStatus::Missing);
    }
}
