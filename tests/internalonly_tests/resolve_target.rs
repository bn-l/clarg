use clarg::internalonly::resolve_target;
use std::env;
use tempfile::TempDir;

// ============================================================================
// Absolute paths
// ============================================================================

#[test]
fn test_resolve_target_absolute_path_unchanged() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("/etc/passwd", tmp.path());
    assert_eq!(result.to_str().unwrap(), "/etc/passwd");
}

#[test]
fn test_resolve_target_absolute_with_dots_normalized() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("/home/./user/../admin", tmp.path());
    assert_eq!(result.to_str().unwrap(), "/home/admin");
}

// ============================================================================
// Relative paths
// ============================================================================

#[test]
fn test_resolve_target_relative_joined_to_root() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("src/main.rs", tmp.path());
    let expected = tmp.path().join("src/main.rs");
    assert_eq!(result, expected);
}

#[test]
fn test_resolve_target_relative_with_dots_normalized() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("./src/../lib/mod.rs", tmp.path());
    let expected = tmp.path().join("lib/mod.rs");
    assert_eq!(result, expected);
}

#[test]
fn test_resolve_target_dotslash_prefix() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("./file.txt", tmp.path());
    let expected = tmp.path().join("file.txt");
    assert_eq!(result, expected);
}

// ============================================================================
// Tilde expansion
// ============================================================================

#[test]
fn test_resolve_target_tilde_expanded() {
    let tmp = TempDir::new().unwrap();
    let home = env::var("HOME").unwrap_or_default();
    let result = resolve_target("~/.config", tmp.path());
    assert_eq!(result.to_str().unwrap(), format!("{}/.config", home));
}

#[test]
fn test_resolve_target_tilde_only() {
    let tmp = TempDir::new().unwrap();
    let home = env::var("HOME").unwrap_or_default();
    let result = resolve_target("~", tmp.path());
    assert_eq!(result.to_str().unwrap(), home);
}

// ============================================================================
// $HOME expansion
// ============================================================================

#[test]
fn test_resolve_target_dollar_home_expanded() {
    let tmp = TempDir::new().unwrap();
    let home = env::var("HOME").unwrap_or_default();
    let result = resolve_target("$HOME/.config", tmp.path());
    assert_eq!(result.to_str().unwrap(), format!("{}/.config", home));
}

// ============================================================================
// Complex paths
// ============================================================================

#[test]
fn test_resolve_target_relative_with_parent_dir() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("../outside", tmp.path());
    // Should be normalized: project_root/../outside -> parent of project_root + /outside
    let parent = tmp.path().parent().unwrap();
    let expected = parent.join("outside");
    assert_eq!(result, expected);
}

#[test]
fn test_resolve_target_many_parent_dirs() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("../../../way/outside", tmp.path());
    // The path goes up multiple levels
    assert!(result.to_str().unwrap().contains("outside"));
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_resolve_target_empty_string() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("", tmp.path());
    // Empty string becomes current dir (project root)
    assert_eq!(result, tmp.path().join("."));
}

#[test]
fn test_resolve_target_single_dot() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target(".", tmp.path());
    assert_eq!(result, tmp.path());
}

#[test]
fn test_resolve_target_with_spaces() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("my file.txt", tmp.path());
    let expected = tmp.path().join("my file.txt");
    assert_eq!(result, expected);
}

#[test]
fn test_resolve_target_unicode() {
    let tmp = TempDir::new().unwrap();
    let result = resolve_target("文档/文件.txt", tmp.path());
    let expected = tmp.path().join("文档/文件.txt");
    assert_eq!(result, expected);
}
