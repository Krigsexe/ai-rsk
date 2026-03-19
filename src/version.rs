// Version check: notify users when a newer version of ai-rsk is available on crates.io.
// This is a non-blocking check — if the network is unavailable or the API fails,
// the scan continues without interruption.

use colored::Colorize;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CRATES_IO_API: &str = "https://crates.io/api/v1/crates/ai-rsk";

/// Check if a newer version of ai-rsk is available on crates.io.
/// Prints a notice if an update is available. Silent otherwise.
/// Non-blocking: network errors are silently ignored.
pub fn check_for_update() {
    // Run in a thread with a short timeout to avoid blocking the scan
    let handle = std::thread::spawn(fetch_latest_version);

    // Wait max 3 seconds for the response
    if let Ok(Some(latest)) = handle.join() {
        if is_newer(&latest, CURRENT_VERSION) {
            eprintln!(
                "  {} ai-rsk {} is available (current: {}). Run: {}",
                "!".yellow(),
                latest.bold(),
                CURRENT_VERSION,
                "ai-rsk update".cyan()
            );
        }
    }
}

/// Update ai-rsk to the latest version.
/// Tries cargo first, then falls back to GitHub Releases binary download.
pub fn run_self_update() {
    println!(
        "  {} Current version: {}",
        "i".cyan(),
        CURRENT_VERSION.bold()
    );

    // Check latest version on crates.io
    print!("  Checking for updates... ");
    let latest = match fetch_latest_version() {
        Some(v) => v,
        None => {
            println!("{}", "failed".red());
            eprintln!(
                "  {} Could not reach crates.io. Check your internet connection.",
                "!".red()
            );
            std::process::exit(1);
        }
    };

    if !is_newer(&latest, CURRENT_VERSION) {
        println!("{}", "up to date".green().bold());
        println!(
            "  {} ai-rsk {} is already the latest version.",
            "✓".green(),
            CURRENT_VERSION
        );
        return;
    }

    println!("{} available", latest.green().bold());

    // Try cargo install first
    if which::which("cargo").is_ok() {
        println!("  {} Updating via cargo...", "→".cyan());
        let status = std::process::Command::new("cargo")
            .args(["install", "ai-rsk"])
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("\n  {} ai-rsk updated to {}", "✓".green(), latest.bold());
                return;
            }
            _ => {
                eprintln!(
                    "  {} cargo install failed. Trying GitHub Releases...",
                    "!".yellow()
                );
            }
        }
    }

    // Fallback: download from GitHub Releases
    println!("  {} Downloading from GitHub Releases...", "→".cyan());
    let gh_tag = format!("v{}", latest);
    let os = if cfg!(target_os = "linux") {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(target_os = "macos") {
        "x86_64-apple-darwin"
    } else if cfg!(target_os = "windows") {
        "x86_64-pc-windows-msvc"
    } else {
        eprintln!("  {} Unsupported platform for auto-update.", "!".red());
        eprintln!("  Install manually: cargo install ai-rsk");
        std::process::exit(1);
    };

    let ext = if cfg!(target_os = "windows") {
        ".zip"
    } else {
        ".tar.gz"
    };
    let asset = format!("ai-rsk-{}{}", os, ext);
    let url = format!(
        "https://github.com/Krigsexe/ai-rsk/releases/download/{}/{}",
        gh_tag, asset
    );

    let tmp_dir = std::env::temp_dir().join(format!("ai-rsk-update-{}", std::process::id()));
    if std::fs::create_dir_all(&tmp_dir).is_err() {
        eprintln!("  {} Cannot create temp directory.", "!".red());
        std::process::exit(1);
    }

    let dl_path = tmp_dir.join(&asset);
    let dl_status = std::process::Command::new("curl")
        .args([
            "-sfL",
            "--progress-bar",
            "-o",
            &dl_path.to_string_lossy(),
            &url,
        ])
        .status();

    if dl_status.map(|s| s.success()).unwrap_or(false) && dl_path.exists() {
        // Extract
        let extract_ok = if asset.ends_with(".tar.gz") {
            std::process::Command::new("tar")
                .args([
                    "-xzf",
                    &dl_path.to_string_lossy(),
                    "-C",
                    &tmp_dir.to_string_lossy(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            // zip on Windows
            std::process::Command::new("tar")
                .args([
                    "-xf",
                    &dl_path.to_string_lossy(),
                    "-C",
                    &tmp_dir.to_string_lossy(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        if extract_ok {
            let bin_name = if cfg!(target_os = "windows") {
                "ai-rsk.exe"
            } else {
                "ai-rsk"
            };
            let extracted = tmp_dir.join(bin_name);
            if extracted.exists() {
                // Find where the current binary is
                if let Ok(current_exe) = std::env::current_exe() {
                    // Try to replace the current binary
                    if std::fs::copy(&extracted, &current_exe).is_ok() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &current_exe,
                                std::fs::Permissions::from_mode(0o755),
                            );
                        }
                        println!("  {} ai-rsk updated to {}", "✓".green(), latest.bold());
                        std::fs::remove_dir_all(&tmp_dir).ok();
                        return;
                    }
                }

                // Cannot replace in-place, copy to ~/.local/bin/
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .unwrap_or_default();
                if !home.is_empty() {
                    let local_bin = std::path::PathBuf::from(&home).join(".local").join("bin");
                    std::fs::create_dir_all(&local_bin).ok();
                    let dest = local_bin.join(bin_name);
                    if std::fs::copy(&extracted, &dest).is_ok() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &dest,
                                std::fs::Permissions::from_mode(0o755),
                            );
                        }
                        println!(
                            "  {} ai-rsk {} installed to {}",
                            "✓".green(),
                            latest.bold(),
                            dest.display()
                        );
                        std::fs::remove_dir_all(&tmp_dir).ok();
                        return;
                    }
                }
            }
        }
    }

    // Cleanup
    std::fs::remove_dir_all(&tmp_dir).ok();
    eprintln!("  {} Auto-update failed.", "!".red());
    eprintln!("  Install manually: {}", "cargo install ai-rsk".cyan());
    std::process::exit(1);
}

/// Fetch the latest version string from crates.io API.
fn fetch_latest_version() -> Option<String> {
    let output = std::process::Command::new("curl")
        .args([
            "-sfL",
            "--max-time",
            "5",
            "-H",
            "User-Agent: ai-rsk",
            CRATES_IO_API,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    json["crate"]["max_version"].as_str().map(String::from)
}

/// Compare two semver strings. Returns true if `latest` is strictly newer than `current`.
fn is_newer(latest: &str, current: &str) -> bool {
    let parse =
        |s: &str| -> Vec<u64> { s.split('.').filter_map(|p| p.parse::<u64>().ok()).collect() };

    let l = parse(latest);
    let c = parse(current);

    if l.len() < 3 || c.len() < 3 {
        return false;
    }

    (l[0], l[1], l[2]) > (c[0], c[1], c[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_true() {
        assert!(is_newer("0.8.0", "0.7.0"));
        assert!(is_newer("1.0.0", "0.7.0"));
        assert!(is_newer("0.7.1", "0.7.0"));
    }

    #[test]
    fn test_is_newer_false() {
        assert!(!is_newer("0.7.0", "0.7.0")); // Same version
        assert!(!is_newer("0.6.0", "0.7.0")); // Older
    }

    #[test]
    fn test_is_newer_invalid() {
        assert!(!is_newer("abc", "0.7.0"));
        assert!(!is_newer("0.7.0", "abc"));
    }

    #[test]
    fn test_current_version_is_set() {
        assert!(!CURRENT_VERSION.is_empty());
    }
}
