use clarg::blocked_files::BlockedFilesRule;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Simple filename matching
// ============================================================================

#[test]
fn test_check_exact_filename_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new(".env")).is_some());
}

#[test]
fn test_check_exact_filename_no_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new(".envrc")).is_none());
}

#[test]
fn test_check_filename_in_subdirectory() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("config/.env")).is_some());
}

#[test]
fn test_check_filename_deeply_nested() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("a/b/c/d/e/.env")).is_some());
}

// ============================================================================
// Wildcard patterns (*)
// ============================================================================

#[test]
fn test_check_star_extension_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["*.secret".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("password.secret")).is_some());
    assert!(rule.check(Path::new("api.secret")).is_some());
}

#[test]
fn test_check_star_extension_no_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["*.secret".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("password.txt")).is_none());
    assert!(rule.check(Path::new("secret")).is_none());
}

#[test]
fn test_check_star_prefix_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["secret*".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("secret.txt")).is_some());
    assert!(rule.check(Path::new("secrets")).is_some());
    assert!(rule.check(Path::new("secret-key.pem")).is_some());
}

#[test]
fn test_check_star_middle_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["test*.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("test1.txt")).is_some());
    assert!(rule.check(Path::new("test_file.txt")).is_some());
    assert!(rule.check(Path::new("test.txt")).is_some());
}

// ============================================================================
// Double-star patterns (**)
// ============================================================================

#[test]
fn test_check_doublestar_match_any_depth() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["**/.env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new(".env")).is_some());
    assert!(rule.check(Path::new("a/.env")).is_some());
    assert!(rule.check(Path::new("a/b/c/.env")).is_some());
}

#[test]
fn test_check_doublestar_directory_pattern() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["**/secrets/**".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("secrets/file.txt")).is_some());
    assert!(rule.check(Path::new("a/secrets/file.txt")).is_some());
    assert!(rule.check(Path::new("secrets/deep/file.txt")).is_some());
}

#[test]
fn test_check_doublestar_extension() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["**/*.pem".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("key.pem")).is_some());
    assert!(rule.check(Path::new("certs/server.pem")).is_some());
    assert!(rule.check(Path::new("a/b/c/private.pem")).is_some());
}

// ============================================================================
// Question mark patterns (?)
// ============================================================================

#[test]
fn test_check_question_mark_single_char() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["file?.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("file1.txt")).is_some());
    assert!(rule.check(Path::new("filea.txt")).is_some());
}

#[test]
fn test_check_question_mark_no_match_multiple_chars() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["file?.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("file12.txt")).is_none());
    assert!(rule.check(Path::new("file.txt")).is_none());
}

#[test]
fn test_check_multiple_question_marks() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["data??.csv".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("data01.csv")).is_some());
    assert!(rule.check(Path::new("dataAB.csv")).is_some());
    assert!(rule.check(Path::new("data1.csv")).is_none());
}

// ============================================================================
// Character class patterns ([...])
// ============================================================================

#[test]
fn test_check_character_class_digits() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["log[0-9].txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("log0.txt")).is_some());
    assert!(rule.check(Path::new("log5.txt")).is_some());
    assert!(rule.check(Path::new("log9.txt")).is_some());
    assert!(rule.check(Path::new("loga.txt")).is_none());
}

#[test]
fn test_check_character_class_letters() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["file[a-z].txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("filea.txt")).is_some());
    assert!(rule.check(Path::new("filez.txt")).is_some());
    assert!(rule.check(Path::new("file1.txt")).is_none());
}

#[test]
fn test_check_character_class_explicit_chars() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["file[abc].txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("filea.txt")).is_some());
    assert!(rule.check(Path::new("fileb.txt")).is_some());
    assert!(rule.check(Path::new("filec.txt")).is_some());
    assert!(rule.check(Path::new("filed.txt")).is_none());
}

#[test]
fn test_check_negated_character_class() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["file[!0-9].txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("filea.txt")).is_some());
    assert!(rule.check(Path::new("file1.txt")).is_none());
}

// ============================================================================
// Directory patterns (ending with /)
// ============================================================================

#[test]
fn test_check_directory_pattern_matches_dir() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // Use pattern without trailing / for easier matching
    let rule = BlockedFilesRule::new(&["node_modules".to_string()], &project_root).unwrap();

    // Directory pattern should match paths
    let path = project_root.join("node_modules");
    assert!(rule.check(&path).is_some());
}

#[test]
fn test_check_directory_pattern_matches_contents() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let rule = BlockedFilesRule::new(&["node_modules/".to_string()], &project_root).unwrap();

    let path = project_root.join("node_modules/package/index.js");
    assert!(rule.check(&path).is_some());
}

#[test]
fn test_check_directory_pattern_nested() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // Use pattern without trailing / - gitignore will match both files and dirs named vendor
    let rule = BlockedFilesRule::new(&["vendor".to_string()], &project_root).unwrap();

    let path1 = project_root.join("lib/vendor");
    let path2 = project_root.join("lib/vendor/file.txt");
    assert!(rule.check(&path1).is_some());
    assert!(rule.check(&path2).is_some());
}

// ============================================================================
// Anchored patterns (starting with /)
// ============================================================================

#[test]
fn test_check_anchored_pattern_matches_root() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["/root.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("root.txt")).is_some());
}

#[test]
fn test_check_anchored_pattern_no_match_nested() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["/root.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("subdir/root.txt")).is_none());
}

// ============================================================================
// Negation patterns (!)
// ============================================================================

#[test]
fn test_check_negation_excludes_file() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(
        &["*.txt".to_string(), "!important.txt".to_string()],
        tmp.path(),
    ).unwrap();

    assert!(rule.check(Path::new("file.txt")).is_some());
    assert!(rule.check(Path::new("important.txt")).is_none());
}

#[test]
fn test_check_negation_order_matters() {
    let tmp = TempDir::new().unwrap();
    // Negation only works after a pattern has matched
    let rule = BlockedFilesRule::new(
        &["!important.txt".to_string(), "*.txt".to_string()],
        tmp.path(),
    ).unwrap();

    // Both should be blocked because *.txt comes after the negation
    assert!(rule.check(Path::new("file.txt")).is_some());
    assert!(rule.check(Path::new("important.txt")).is_some());
}

// ============================================================================
// Multiple patterns
// ============================================================================

#[test]
fn test_check_multiple_patterns_any_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(
        &[".env".to_string(), "*.secret".to_string(), "*.pem".to_string()],
        tmp.path(),
    ).unwrap();

    assert!(rule.check(Path::new(".env")).is_some());
    assert!(rule.check(Path::new("api.secret")).is_some());
    assert!(rule.check(Path::new("key.pem")).is_some());
    assert!(rule.check(Path::new("readme.md")).is_none());
}

#[test]
fn test_check_multiple_patterns_none_match() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(
        &[".env".to_string(), "*.secret".to_string()],
        tmp.path(),
    ).unwrap();

    assert!(rule.check(Path::new("config.yaml")).is_none());
    assert!(rule.check(Path::new("main.rs")).is_none());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_check_empty_path() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".env".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("")).is_none());
}

#[test]
fn test_check_dot_path() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new(".")).is_some());
}

#[test]
fn test_check_hidden_files_pattern() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&[".*".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new(".env")).is_some());
    assert!(rule.check(Path::new(".gitignore")).is_some());
    assert!(rule.check(Path::new(".config")).is_some());
    assert!(rule.check(Path::new("file.txt")).is_none());
}

#[test]
fn test_check_with_spaces_in_path() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["my file.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("my file.txt")).is_some());
}

#[test]
fn test_check_with_special_chars_in_filename() {
    let tmp = TempDir::new().unwrap();
    let rule = BlockedFilesRule::new(&["file@#$.txt".to_string()], tmp.path()).unwrap();

    assert!(rule.check(Path::new("file@#$.txt")).is_some());
}
