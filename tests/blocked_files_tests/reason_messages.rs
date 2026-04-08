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

#[test]
fn test_reason_directory_pattern_preserves_trailing_slash() {
    // Regression: gix_glob::Pattern's Display impl reconstructs the
    // trailing slash from the MUST_BE_DIR mode flag (text alone has no
    // trailing /). Lock that round-trip so we don't silently regress
    // the user-facing pattern format.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let rule = BlockedFilesRule::new(&["node_modules/".to_string()], &project_root)
        .unwrap();
    let reason = rule
        .check(&project_root.join("node_modules/lib/index.js"))
        .expect("should block via parent walk");
    assert!(
        reason.contains("node_modules/"),
        "expected `node_modules/` (with trailing slash) in reason, got: {reason}"
    );
}

#[test]
fn test_reason_anchored_pattern_preserves_leading_slash() {
    // Companion to the trailing-slash regression: ABSOLUTE-mode
    // patterns must round-trip with their leading `/` via Display.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let rule =
        BlockedFilesRule::new(&["/root.txt".to_string()], &project_root).unwrap();
    let reason = rule
        .check(&project_root.join("root.txt"))
        .expect("should block project-anchored root.txt");
    assert!(
        reason.contains("/root.txt"),
        "expected `/root.txt` (with leading slash) in reason, got: {reason}"
    );
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
