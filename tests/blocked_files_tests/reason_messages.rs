use clarg::blocked_files::BlockedFilesRule;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Reason message format tests
// ============================================================================

#[test]
fn test_reason_contains_blocked_by_clarg() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new(".env")).unwrap();
    assert!(reason.contains("Blocked by `clarg`"));
}

#[test]
fn test_reason_contains_path() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new(".env")).unwrap();
    assert!(reason.contains(".env"));
}

#[test]
fn test_reason_contains_pattern() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["*.secret".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new("api.secret")).unwrap();
    assert!(reason.contains("*.secret"));
}

#[test]
fn test_reason_contains_forbidden() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new(".env")).unwrap();
    assert!(reason.contains("forbidden"));
}

#[test]
fn test_reason_contains_matched() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new(".env")).unwrap();
    assert!(reason.contains("matched"));
}

#[test]
fn test_reason_with_nested_path() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new("config/prod/.env")).unwrap();
    assert!(reason.contains("config/prod/.env"));
}

#[test]
fn test_reason_with_complex_pattern() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["**/*.pem".to_string()], tmp.path()).unwrap();

    let reason = rule.check(Path::new("certs/server.pem")).unwrap();
    assert!(reason.contains("**/*.pem"));
}

// ============================================================================
// No match returns None
// ============================================================================

#[test]
fn test_no_match_returns_none() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("config.yaml")).is_none());
}

#[test]
fn test_empty_patterns_never_matches() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[], tmp.path()).unwrap();

    assert!(rule.check(Path::new(".env")).is_none());
    assert!(rule.check(Path::new("anything")).is_none());
}
