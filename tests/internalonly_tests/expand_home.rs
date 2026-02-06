use clarg::internalonly::expand_home;
use std::env;

// ============================================================================
// Tilde expansion
// ============================================================================

#[test]
fn test_expand_home_tilde_only() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~");
    assert_eq!(result.to_str().unwrap(), home);
}

#[test]
fn test_expand_home_tilde_with_path() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~/Documents");
    assert_eq!(result.to_str().unwrap(), format!("{}/Documents", home));
}

#[test]
fn test_expand_home_tilde_nested_path() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~/a/b/c/d");
    assert_eq!(result.to_str().unwrap(), format!("{}/a/b/c/d", home));
}

#[test]
fn test_expand_home_tilde_with_dots() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~/.config");
    assert_eq!(result.to_str().unwrap(), format!("{}/.config", home));
}

// ============================================================================
// $HOME expansion
// ============================================================================

#[test]
fn test_expand_home_dollar_home_only() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("$HOME");
    assert_eq!(result.to_str().unwrap(), home);
}

#[test]
fn test_expand_home_dollar_home_with_path() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("$HOME/Documents");
    assert_eq!(result.to_str().unwrap(), format!("{}/Documents", home));
}

#[test]
fn test_expand_home_dollar_home_nested_path() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("$HOME/a/b/c");
    assert_eq!(result.to_str().unwrap(), format!("{}/a/b/c", home));
}

// ============================================================================
// Non-expansion cases
// ============================================================================

#[test]
fn test_expand_home_absolute_path_unchanged() {
    let result = expand_home("/etc/passwd");
    assert_eq!(result.to_str().unwrap(), "/etc/passwd");
}

#[test]
fn test_expand_home_relative_path_unchanged() {
    let result = expand_home("src/main.rs");
    assert_eq!(result.to_str().unwrap(), "src/main.rs");
}

#[test]
fn test_expand_home_tilde_in_middle_unchanged() {
    let result = expand_home("/home/~user");
    assert_eq!(result.to_str().unwrap(), "/home/~user");
}

#[test]
fn test_expand_home_dollar_home_in_middle_unchanged() {
    let result = expand_home("/home/$HOME/file");
    assert_eq!(result.to_str().unwrap(), "/home/$HOME/file");
}

#[test]
fn test_expand_home_tilde_without_slash() {
    // ~username pattern is NOT expanded (only ~ and ~/)
    let result = expand_home("~user");
    assert_eq!(result.to_str().unwrap(), "~user");
}

#[test]
fn test_expand_home_empty_string() {
    let result = expand_home("");
    assert_eq!(result.to_str().unwrap(), "");
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_expand_home_tilde_slash_only() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~/");
    assert_eq!(result.to_str().unwrap(), format!("{}/", home));
}

#[test]
fn test_expand_home_dollar_home_slash_only() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("$HOME/");
    assert_eq!(result.to_str().unwrap(), format!("{}/", home));
}

#[test]
fn test_expand_home_other_env_vars_not_expanded() {
    let result = expand_home("$USER/file");
    assert_eq!(result.to_str().unwrap(), "$USER/file");
}

#[test]
fn test_expand_home_curly_brace_syntax_not_expanded() {
    let result = expand_home("${HOME}/file");
    assert_eq!(result.to_str().unwrap(), "${HOME}/file");
}

#[test]
fn test_expand_home_with_spaces() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~/my documents");
    assert_eq!(result.to_str().unwrap(), format!("{}/my documents", home));
}

#[test]
fn test_expand_home_unicode() {
    let home = env::var("HOME").unwrap_or_default();
    let result = expand_home("~/文档");
    assert_eq!(result.to_str().unwrap(), format!("{}/文档", home));
}
