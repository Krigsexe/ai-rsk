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
                "  {} ai-rsk {} is available (current: {}). Update: {}",
                "!".yellow(),
                latest.bold(),
                CURRENT_VERSION,
                "cargo install ai-rsk".cyan()
            );
        }
    }
}

/// Fetch the latest version string from crates.io API.
fn fetch_latest_version() -> Option<String> {
    let output = std::process::Command::new("curl")
        .args(["-sfL", "--max-time", "3", CRATES_IO_API])
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
