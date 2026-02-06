use clarg::blocked_commands::BlockedCommandsRule;

// ============================================================================
// Reason message format tests
// ============================================================================

#[test]
fn test_reason_contains_blocked_by_clarg() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let reason = rule.check("rm -rf /").unwrap();
    assert!(reason.contains("Blocked by `clarg`"));
}

#[test]
fn test_reason_contains_command() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let reason = rule.check("rm -rf /").unwrap();
    assert!(reason.contains("rm -rf /"));
}

#[test]
fn test_reason_contains_pattern() {
    let rule = BlockedCommandsRule::new(&["rm.*-rf".to_string()]).unwrap();
    let reason = rule.check("rm -rf /").unwrap();
    assert!(reason.contains("rm.*-rf"));
}

#[test]
fn test_reason_contains_forbidden() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let reason = rule.check("rm").unwrap();
    assert!(reason.contains("forbidden"));
}

#[test]
fn test_reason_contains_matched() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let reason = rule.check("rm").unwrap();
    assert!(reason.contains("matched"));
}

// ============================================================================
// Command truncation in reason
// ============================================================================

#[test]
fn test_reason_truncates_long_command() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let long_command = format!("rm {}", "a".repeat(200));
    let reason = rule.check(&long_command).unwrap();

    // Command should be truncated to 100 chars
    assert!(reason.len() < long_command.len() + 100);
}

#[test]
fn test_reason_short_command_not_truncated() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let reason = rule.check("rm file.txt").unwrap();
    assert!(reason.contains("rm file.txt"));
}

// ============================================================================
// No match returns None
// ============================================================================

#[test]
fn test_no_match_returns_none() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    assert!(rule.check("ls -la").is_none());
}

#[test]
fn test_empty_patterns_never_matches() {
    let rule = BlockedCommandsRule::new(&[]).unwrap();
    assert!(rule.check("rm -rf /").is_none());
    assert!(rule.check("anything").is_none());
}

#[test]
fn test_empty_command_with_dot_pattern() {
    let rule = BlockedCommandsRule::new(&[".".to_string()]).unwrap();
    // Empty string doesn't match . (which requires at least one char)
    assert!(rule.check("").is_none());
}

// ============================================================================
// Multiple patterns - first match wins
// ============================================================================

#[test]
fn test_first_matching_pattern_in_reason() {
    let rule = BlockedCommandsRule::new(&[
        "rm".to_string(),
        "delete".to_string(),
    ]).unwrap();

    let reason = rule.check("rm file").unwrap();
    assert!(reason.contains("rm"));
}

#[test]
fn test_second_pattern_if_first_doesnt_match() {
    let rule = BlockedCommandsRule::new(&[
        "delete".to_string(),
        "rm".to_string(),
    ]).unwrap();

    let reason = rule.check("rm file").unwrap();
    assert!(reason.contains("rm"));
}

// ============================================================================
// UTF-8 truncation safety
// ============================================================================

#[test]
fn test_truncate_long_unicode_command_no_panic() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    // Create a command with multi-byte UTF-8 characters that exceeds 100 char limit
    let long_unicode = format!("rm {}", "é".repeat(150));
    let reason = rule.check(&long_unicode);
    assert!(reason.is_some(), "should match despite unicode");
}

#[test]
fn test_truncate_cjk_command_no_panic() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let long_cjk = format!("rm {}", "日本語".repeat(50));
    let reason = rule.check(&long_cjk);
    assert!(reason.is_some(), "should match despite CJK characters");
}

#[test]
fn test_truncate_emoji_command_no_panic() {
    let rule = BlockedCommandsRule::new(&["rm".to_string()]).unwrap();
    let long_emoji = format!("rm {}", "🔥".repeat(50));
    let reason = rule.check(&long_emoji);
    assert!(reason.is_some(), "should match despite emoji");
}
