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
fn test_expand_home_tilde_user_resolves_to_platform_home() {
    // `~user` is expanded to the platform-standard home directory so
    // safety rules (internal_access_only, no_system_dirs, no_root) see
    // an absolute path outside the project, matching what bash would
    // actually resolve at runtime.
    let result = expand_home("~alice");
    let s = result.to_str().unwrap();
    #[cfg(target_os = "macos")]
    assert_eq!(s, "/Users/alice");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(s, "/home/alice");
}

#[test]
fn test_expand_home_tilde_user_with_path() {
    let result = expand_home("~alice/Documents/notes.txt");
    let s = result.to_str().unwrap();
    #[cfg(target_os = "macos")]
    assert_eq!(s, "/Users/alice/Documents/notes.txt");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(s, "/home/alice/Documents/notes.txt");
}

#[test]
fn test_expand_home_tilde_root_lands_in_system_dir() {
    // `~root` is the high-value case: it must land somewhere inside
    // SYSTEM_DIRS so `no_system_dirs` can block it.
    let result = expand_home("~root/.bashrc");
    let s = result.to_str().unwrap();
    #[cfg(target_os = "macos")]
    assert_eq!(s, "/var/root/.bashrc");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(s, "/root/.bashrc");
}

#[test]
fn test_expand_home_tilde_root_no_path() {
    let result = expand_home("~root");
    let s = result.to_str().unwrap();
    #[cfg(target_os = "macos")]
    assert_eq!(s, "/var/root");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(s, "/root");
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

// ============================================================================
// Bash special tilde forms — NOT treated as `~user` (regression for
// `~+` / `~-` / `~N` being expanded to synthetic homes like `/Users/+`)
// ============================================================================
//
// Bash reserves `~+` (=$PWD), `~-` (=$OLDPWD), `~N`, `~+N`, and `~-N`
// (dirstack refs) as special prefixes — they are NOT login-name
// lookups. `expand_home` must therefore leave them as literal so the
// caller resolves them relative to the project root.

#[test]
fn test_expand_home_tilde_plus_left_literal() {
    // `~+` alone or `~+/...` must NOT resolve to `/Users/+` or similar.
    let result = expand_home("~+/Cargo.toml");
    assert_eq!(result.to_str().unwrap(), "~+/Cargo.toml");
}

#[test]
fn test_expand_home_tilde_plus_alone_literal() {
    let result = expand_home("~+");
    assert_eq!(result.to_str().unwrap(), "~+");
}

#[test]
fn test_expand_home_tilde_minus_left_literal() {
    let result = expand_home("~-/foo");
    assert_eq!(result.to_str().unwrap(), "~-/foo");
}

#[test]
fn test_expand_home_tilde_minus_alone_literal() {
    let result = expand_home("~-");
    assert_eq!(result.to_str().unwrap(), "~-");
}

#[test]
fn test_expand_home_tilde_digit_left_literal() {
    // `~0` / `~1` etc. are dirstack refs, not login names.
    let result = expand_home("~0/foo");
    assert_eq!(result.to_str().unwrap(), "~0/foo");
}

#[test]
fn test_expand_home_tilde_plus_digit_left_literal() {
    let result = expand_home("~+2/foo");
    assert_eq!(result.to_str().unwrap(), "~+2/foo");
}

#[test]
fn test_expand_home_tilde_minus_digit_left_literal() {
    let result = expand_home("~-1/foo");
    assert_eq!(result.to_str().unwrap(), "~-1/foo");
}

#[test]
fn test_expand_home_tilde_punctuation_left_literal() {
    // Anything that isn't a valid login-name shape falls through.
    let result = expand_home("~!/foo");
    assert_eq!(result.to_str().unwrap(), "~!/foo");
}

#[test]
fn test_expand_home_tilde_with_dash_after_alpha_still_resolves() {
    // `~user-name` IS a valid login name (first char alpha, dashes allowed after).
    let result = expand_home("~user-name/foo");
    let s = result.to_str().unwrap();
    #[cfg(target_os = "macos")]
    assert_eq!(s, "/Users/user-name/foo");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(s, "/home/user-name/foo");
}
