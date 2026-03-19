use crate::types::Ecosystem;
use std::path::Path;

/// Detect which ecosystems are present in the project by checking for marker files.
/// A project can have multiple ecosystems (e.g., monorepo with JS + Python).
pub fn detect_ecosystems(project_path: &Path) -> Vec<Ecosystem> {
    let mut ecosystems = Vec::new();

    // JavaScript/TypeScript: package.json
    if project_path.join("package.json").exists() {
        ecosystems.push(Ecosystem::JavaScript);
    }

    // Python: requirements.txt, pyproject.toml, setup.py, setup.cfg, Pipfile, or requirements/ dir
    if project_path.join("requirements.txt").exists()
        || project_path.join("pyproject.toml").exists()
        || project_path.join("setup.py").exists()
        || project_path.join("setup.cfg").exists()
        || project_path.join("Pipfile").exists()
        || project_path.join("requirements").is_dir()
    {
        ecosystems.push(Ecosystem::Python);
    }

    // Go: go.mod
    if project_path.join("go.mod").exists() {
        ecosystems.push(Ecosystem::Go);
    }

    // Rust: Cargo.toml
    if project_path.join("Cargo.toml").exists() {
        ecosystems.push(Ecosystem::Rust);
    }

    ecosystems
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_detect_javascript() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("package.json"), "{}").expect("Failed to write");
        let ecosystems = detect_ecosystems(dir.path());
        assert_eq!(ecosystems, vec![Ecosystem::JavaScript]);
    }

    #[test]
    fn test_detect_python_requirements() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("requirements.txt"), "flask").expect("Failed to write");
        let ecosystems = detect_ecosystems(dir.path());
        assert_eq!(ecosystems, vec![Ecosystem::Python]);
    }

    #[test]
    fn test_detect_python_pyproject() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("pyproject.toml"), "[project]").expect("Failed to write");
        let ecosystems = detect_ecosystems(dir.path());
        assert_eq!(ecosystems, vec![Ecosystem::Python]);
    }

    #[test]
    fn test_detect_go() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("go.mod"), "module example").expect("Failed to write");
        let ecosystems = detect_ecosystems(dir.path());
        assert_eq!(ecosystems, vec![Ecosystem::Go]);
    }

    #[test]
    fn test_detect_rust() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]").expect("Failed to write");
        let ecosystems = detect_ecosystems(dir.path());
        assert_eq!(ecosystems, vec![Ecosystem::Rust]);
    }

    #[test]
    fn test_detect_multiple_ecosystems() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::write(dir.path().join("package.json"), "{}").expect("Failed to write");
        fs::write(dir.path().join("requirements.txt"), "flask").expect("Failed to write");
        let ecosystems = detect_ecosystems(dir.path());
        assert_eq!(ecosystems, vec![Ecosystem::JavaScript, Ecosystem::Python]);
    }

    #[test]
    fn test_detect_empty_project() {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let ecosystems = detect_ecosystems(dir.path());
        assert!(ecosystems.is_empty());
    }
}
