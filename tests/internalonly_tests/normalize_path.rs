use clarg::internalonly::normalize_path;
use std::path::Path;

// ============================================================================
// Basic normalization
// ============================================================================

#[test]
fn test_normalize_simple_path() {
    let result = normalize_path(Path::new("/home/user/project"));
    assert_eq!(result.to_str().unwrap(), "/home/user/project");
}

#[test]
fn test_normalize_relative_path() {
    let result = normalize_path(Path::new("src/main.rs"));
    assert_eq!(result.to_str().unwrap(), "src/main.rs");
}

#[test]
fn test_normalize_empty_path() {
    let result = normalize_path(Path::new(""));
    assert_eq!(result.to_str().unwrap(), ".");
}

// ============================================================================
// Dot (.) handling
// ============================================================================

#[test]
fn test_normalize_single_dot() {
    let result = normalize_path(Path::new("."));
    assert_eq!(result.to_str().unwrap(), ".");
}

#[test]
fn test_normalize_removes_single_dots() {
    let result = normalize_path(Path::new("/home/./user/./project"));
    assert_eq!(result.to_str().unwrap(), "/home/user/project");
}

#[test]
fn test_normalize_leading_dot() {
    let result = normalize_path(Path::new("./src/main.rs"));
    assert_eq!(result.to_str().unwrap(), "src/main.rs");
}

#[test]
fn test_normalize_trailing_dot() {
    let result = normalize_path(Path::new("/home/user/."));
    assert_eq!(result.to_str().unwrap(), "/home/user");
}

#[test]
fn test_normalize_multiple_consecutive_dots() {
    let result = normalize_path(Path::new("/home/./././user"));
    assert_eq!(result.to_str().unwrap(), "/home/user");
}

// ============================================================================
// Double dot (..) handling
// ============================================================================

#[test]
fn test_normalize_double_dot_pops_directory() {
    let result = normalize_path(Path::new("/home/user/../admin"));
    assert_eq!(result.to_str().unwrap(), "/home/admin");
}

#[test]
fn test_normalize_multiple_double_dots() {
    let result = normalize_path(Path::new("/home/user/project/../../admin"));
    assert_eq!(result.to_str().unwrap(), "/home/admin");
}

#[test]
fn test_normalize_double_dot_at_root_stays_at_root() {
    let result = normalize_path(Path::new("/../../../etc"));
    assert_eq!(result.to_str().unwrap(), "/etc");
}

#[test]
fn test_normalize_double_dot_with_no_parent() {
    // Relative path with .. that can't be resolved
    let result = normalize_path(Path::new("../outside"));
    assert_eq!(result.to_str().unwrap(), "../outside");
}

#[test]
fn test_normalize_double_dot_exceeds_path() {
    let result = normalize_path(Path::new("a/b/../../../c"));
    assert_eq!(result.to_str().unwrap(), "../c");
}

#[test]
fn test_normalize_double_dot_at_end() {
    let result = normalize_path(Path::new("/home/user/project/.."));
    assert_eq!(result.to_str().unwrap(), "/home/user");
}

// ============================================================================
// Mixed . and .. handling
// ============================================================================

#[test]
fn test_normalize_mixed_dots() {
    let result = normalize_path(Path::new("/home/./user/../admin/./project"));
    assert_eq!(result.to_str().unwrap(), "/home/admin/project");
}

#[test]
fn test_normalize_complex_path() {
    let result = normalize_path(Path::new("/a/b/c/./../../d/../e/f"));
    assert_eq!(result.to_str().unwrap(), "/a/e/f");
}

// ============================================================================
// Absolute vs relative paths
// ============================================================================

#[test]
fn test_normalize_preserves_absolute() {
    let result = normalize_path(Path::new("/absolute/path"));
    assert!(result.is_absolute());
}

#[test]
fn test_normalize_preserves_relative() {
    let result = normalize_path(Path::new("relative/path"));
    assert!(result.is_relative());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_normalize_root_only() {
    let result = normalize_path(Path::new("/"));
    assert_eq!(result.to_str().unwrap(), "/");
}

#[test]
fn test_normalize_single_component() {
    let result = normalize_path(Path::new("file.txt"));
    assert_eq!(result.to_str().unwrap(), "file.txt");
}

#[test]
fn test_normalize_trailing_slash() {
    let result = normalize_path(Path::new("/home/user/"));
    assert_eq!(result.to_str().unwrap(), "/home/user");
}

#[test]
fn test_normalize_double_slash() {
    let result = normalize_path(Path::new("/home//user"));
    // Path handles this - double slashes become single
    assert_eq!(result.to_str().unwrap(), "/home/user");
}

#[test]
fn test_normalize_path_with_spaces() {
    let result = normalize_path(Path::new("/home/my user/my project"));
    assert_eq!(result.to_str().unwrap(), "/home/my user/my project");
}

#[test]
fn test_normalize_path_with_special_chars() {
    let result = normalize_path(Path::new("/home/user/@#$/file"));
    assert_eq!(result.to_str().unwrap(), "/home/user/@#$/file");
}

#[test]
fn test_normalize_unicode_path() {
    let result = normalize_path(Path::new("/home/用户/项目"));
    assert_eq!(result.to_str().unwrap(), "/home/用户/项目");
}
