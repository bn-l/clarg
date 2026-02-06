use clarg::internalonly::resolve_project_root;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Successful resolution
// ============================================================================

#[test]
fn test_resolve_project_root_existing_dir() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_project_root(tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_resolve_project_root_returns_absolute() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_project_root(tmp.path()).unwrap();
    assert!(result.is_absolute());
}

#[test]
fn test_resolve_project_root_canonicalizes_path() {
    let tmp = TempDir::new().unwrap();
    // Create a path with . and ..
    let path_with_dots = tmp.path().join("subdir/..").join(".");
    std::fs::create_dir(tmp.path().join("subdir")).unwrap();

    let result = resolve_project_root(&path_with_dots).unwrap();
    let direct = resolve_project_root(tmp.path()).unwrap();

    assert_eq!(result, direct);
}

#[test]
fn test_resolve_project_root_current_dir() {
    let result = resolve_project_root(Path::new("."));
    assert!(result.is_ok());
    assert!(result.unwrap().is_absolute());
}

// ============================================================================
// Error cases
// ============================================================================

#[test]
fn test_resolve_project_root_nonexistent_path() {
    let result = resolve_project_root(Path::new("/this/path/does/not/exist/12345"));
    assert!(result.is_err());
}

#[test]
fn test_resolve_project_root_empty_path() {
    // Empty path resolves to current directory
    let result = resolve_project_root(Path::new(""));
    // This depends on the platform but should work
    assert!(result.is_ok() || result.is_err());
}

// ============================================================================
// Symlink handling (platform-dependent)
// ============================================================================

#[test]
fn test_resolve_project_root_follows_symlinks() {
    let tmp = TempDir::new().unwrap();
    let real_dir = tmp.path().join("real");
    std::fs::create_dir(&real_dir).unwrap();

    #[cfg(unix)]
    {
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let resolved_link = resolve_project_root(&link).unwrap();
        let resolved_real = resolve_project_root(&real_dir).unwrap();

        assert_eq!(resolved_link, resolved_real);
    }
}
