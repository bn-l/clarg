use clarg::bash_analyzer::looks_like_path;

// ============================================================================
// Paths with slashes
// ============================================================================

#[test]
fn test_absolute_path_looks_like_path() {
    assert!(looks_like_path("/etc/passwd"));
}

#[test]
fn test_relative_path_with_slash_looks_like_path() {
    assert!(looks_like_path("src/main.rs"));
}

#[test]
fn test_deep_path_looks_like_path() {
    assert!(looks_like_path("a/b/c/d/e/f"));
}

#[test]
fn test_trailing_slash_looks_like_path() {
    assert!(looks_like_path("directory/"));
}

// ============================================================================
// Paths starting with .
// ============================================================================

#[test]
fn test_dot_prefix_looks_like_path() {
    assert!(looks_like_path("./file.txt"));
}

#[test]
fn test_dotdot_prefix_looks_like_path() {
    assert!(looks_like_path("../parent"));
}

#[test]
fn test_hidden_file_looks_like_path() {
    assert!(looks_like_path(".env"));
}

#[test]
fn test_hidden_directory_looks_like_path() {
    assert!(looks_like_path(".git"));
}

#[test]
fn test_dot_only_looks_like_path() {
    assert!(looks_like_path("."));
}

#[test]
fn test_dotdot_only_looks_like_path() {
    assert!(looks_like_path(".."));
}

// ============================================================================
// Paths starting with ~
// ============================================================================

#[test]
fn test_tilde_looks_like_path() {
    assert!(looks_like_path("~"));
}

#[test]
fn test_tilde_slash_looks_like_path() {
    assert!(looks_like_path("~/Documents"));
}

#[test]
fn test_tilde_user_looks_like_path() {
    assert!(looks_like_path("~user"));
}

// ============================================================================
// Paths with $HOME
// ============================================================================

#[test]
fn test_home_var_looks_like_path() {
    assert!(looks_like_path("$HOME"));
}

#[test]
fn test_home_var_with_path_looks_like_path() {
    assert!(looks_like_path("$HOME/.config"));
}

// ============================================================================
// Non-paths
// ============================================================================

#[test]
fn test_simple_word_not_path() {
    assert!(!looks_like_path("hello"));
}

#[test]
fn test_flag_not_path() {
    assert!(!looks_like_path("-v"));
}

#[test]
fn test_long_flag_not_path() {
    assert!(!looks_like_path("--verbose"));
}

#[test]
fn test_number_not_path() {
    assert!(!looks_like_path("123"));
}

#[test]
fn test_command_not_path() {
    assert!(!looks_like_path("ls"));
}

#[test]
fn test_pattern_not_path() {
    assert!(!looks_like_path("*.txt"));
}

#[test]
fn test_url_looks_like_path() {
    // URLs contain / so they look like paths
    assert!(looks_like_path("https://example.com/page"));
}

#[test]
fn test_env_var_other_not_path() {
    assert!(!looks_like_path("$USER"));
}

#[test]
fn test_empty_not_path() {
    assert!(!looks_like_path(""));
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_just_slash_looks_like_path() {
    assert!(looks_like_path("/"));
}

#[test]
fn test_double_slash_looks_like_path() {
    assert!(looks_like_path("//"));
}

#[test]
fn test_word_containing_dot_not_path() {
    // "file.txt" doesn't start with . and has no /
    assert!(!looks_like_path("file.txt"));
}

#[test]
fn test_word_with_at_sign_not_path() {
    assert!(!looks_like_path("user@host"));
}
