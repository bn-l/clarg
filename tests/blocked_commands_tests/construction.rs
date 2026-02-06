use clarg::blocked_commands::BlockedCommandsRule;

// ============================================================================
// BlockedCommandsRule::new() - Valid patterns
// ============================================================================

#[test]
fn test_new_with_empty_patterns() {
    let result = BlockedCommandsRule::new(&[]);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_single_literal_pattern() {
    let patterns = vec!["rm".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_multiple_patterns() {
    let patterns = vec![
        "rm".to_string(),
        "mv".to_string(),
        "dd".to_string(),
    ];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_regex_pattern() {
    let patterns = vec!["rm.*-rf".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_anchored_regex() {
    let patterns = vec!["^sudo".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_end_anchored_regex() {
    let patterns = vec!["--force$".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_character_class() {
    let patterns = vec![r"\d+".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_alternation() {
    let patterns = vec!["(rm|mv|cp)".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_word_boundary() {
    let patterns = vec![r"\brm\b".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_whitespace_pattern() {
    let patterns = vec![r"rm\s+-rf".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_many_patterns() {
    let patterns: Vec<String> = (0..100).map(|i| format!("pattern{}", i)).collect();
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}

// ============================================================================
// BlockedCommandsRule::new() - Invalid patterns
// ============================================================================

#[test]
fn test_new_with_invalid_regex_unclosed_paren() {
    let patterns = vec!["(unclosed".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_err());
}

#[test]
fn test_new_with_invalid_regex_unclosed_bracket() {
    let patterns = vec!["[unclosed".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_err());
}

#[test]
fn test_new_with_invalid_regex_bad_escape() {
    let patterns = vec![r"\".to_string()]; // Trailing backslash
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_err());
}

#[test]
fn test_new_with_invalid_quantifier() {
    let patterns = vec!["*invalid".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_err());
}

#[test]
fn test_new_with_invalid_repetition() {
    let patterns = vec!["a{invalid}".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_err());
}

// ============================================================================
// BlockedCommandsRule::new() - Edge cases
// ============================================================================

#[test]
fn test_new_with_empty_string_pattern() {
    let patterns = vec!["".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    // Empty regex is valid and matches everything
    assert!(result.is_ok());
}

#[test]
fn test_new_with_dot_pattern() {
    let patterns = vec![".".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    // Single dot is valid regex matching any char
    assert!(result.is_ok());
}

#[test]
fn test_new_with_complex_regex() {
    let patterns = vec![r"^(sudo\s+)?(rm|mv|cp)\s+(-[rRfvi]+\s+)*(/|~)".to_string()];
    let result = BlockedCommandsRule::new(&patterns);
    assert!(result.is_ok());
}
