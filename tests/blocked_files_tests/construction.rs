use clarg::blocked_files::BlockedFilesRule;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// BlockedFilesRule::new() - Valid patterns
// ============================================================================

#[test]
fn test_new_with_empty_patterns() {
    let tmp = TempDir::new().unwrap();
    let result = BlockedFilesRule::new(&[], tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_single_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec![".env".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_multiple_patterns() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec![
        ".env".to_string(),
        "*.secret".to_string(),
        "node_modules/".to_string(),
    ];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_glob_star_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["**/*.env".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_negation_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["*.txt".to_string(), "!important.txt".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_directory_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["logs/".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_anchored_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["/root-only.txt".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_character_class_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["file[0-9].txt".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_question_mark_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["file?.txt".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_many_patterns() {
    let tmp = TempDir::new().unwrap();
    let patterns: Vec<String> = (0..100).map(|i| format!("pattern{}.txt", i)).collect();
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

// ============================================================================
// BlockedFilesRule::new() - Patterns that look invalid
// Note: The ignore crate is quite lenient with patterns and treats unclosed
// brackets as literal characters rather than errors
// ============================================================================

#[test]
fn test_new_with_unclosed_bracket_treated_literally() {
    let tmp = TempDir::new().unwrap();
    // Unclosed bracket is treated as literal character by the ignore crate
    let patterns = vec!["[invalid".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_unclosed_character_class_treated_literally() {
    let tmp = TempDir::new().unwrap();
    // Unclosed character class is treated as literal by the ignore crate
    let patterns = vec!["file[abc".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

// ============================================================================
// BlockedFilesRule::new() - Project root handling
// ============================================================================

#[test]
fn test_new_with_absolute_project_root() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec![".env".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_relative_project_root() {
    let patterns = vec![".env".to_string()];
    let result = BlockedFilesRule::new(&patterns, Path::new("."));
    assert!(result.is_ok());
}

// ============================================================================
// BlockedFilesRule::new() - Unicode patterns
// ============================================================================

#[test]
fn test_new_with_unicode_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["文档.txt".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_emoji_pattern() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec!["🔒secret.txt".to_string()];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}

#[test]
fn test_new_with_mixed_unicode_patterns() {
    let tmp = TempDir::new().unwrap();
    let patterns = vec![
        "файл.txt".to_string(),
        "αρχείο.doc".to_string(),
        "ファイル.pdf".to_string(),
    ];
    let result = BlockedFilesRule::new(&patterns, tmp.path());
    assert!(result.is_ok());
}
