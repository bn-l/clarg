use clarg::output::format_log_entry;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// format_log_entry tests
// ============================================================================

#[test]
fn test_format_log_entry_basic() {
    let result = format_log_entry("Bash", "deny", "dangerous command");

    assert!(result.contains("tool=Bash"));
    assert!(result.contains("verdict=deny"));
    assert!(result.contains("reason=dangerous command"));
}

#[test]
fn test_format_log_entry_contains_all_parts() {
    let result = format_log_entry("Read", "allow", "safe file");

    assert!(result.contains("tool=Read"));
    assert!(result.contains("verdict=allow"));
    assert!(result.contains("reason=safe file"));
}

#[test]
fn test_format_log_entry_contains_timestamp() {
    let result = format_log_entry("Write", "deny", "test");

    // Should start with timestamp in brackets
    assert!(result.starts_with('['));
    assert!(result.contains(']'));

    // Extract timestamp and verify it's a valid number
    let timestamp_end = result.find(']').unwrap();
    let timestamp_str = &result[1..timestamp_end];
    let timestamp: u64 = timestamp_str.parse().unwrap();

    // Timestamp should be reasonable (after 2020 and before 2030)
    assert!(timestamp > 1577836800); // Jan 1, 2020
    assert!(timestamp < 1893456000); // Jan 1, 2030
}

#[test]
fn test_format_log_entry_timestamp_is_current() {
    let result = format_log_entry("Test", "allow", "test");

    let timestamp_end = result.find(']').unwrap();
    let timestamp_str = &result[1..timestamp_end];
    let log_timestamp: u64 = timestamp_str.parse().unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Timestamp should be within 5 seconds of now
    let diff = if now > log_timestamp {
        now - log_timestamp
    } else {
        log_timestamp - now
    };
    assert!(diff < 5);
}

#[test]
fn test_format_log_entry_with_bash_tool() {
    let result = format_log_entry("Bash", "deny", "rm -rf command");
    assert!(result.contains("tool=Bash"));
}

#[test]
fn test_format_log_entry_with_read_tool() {
    let result = format_log_entry("Read", "allow", "reading file");
    assert!(result.contains("tool=Read"));
}

#[test]
fn test_format_log_entry_with_write_tool() {
    let result = format_log_entry("Write", "deny", "blocked path");
    assert!(result.contains("tool=Write"));
}

#[test]
fn test_format_log_entry_with_edit_tool() {
    let result = format_log_entry("Edit", "allow", "editing file");
    assert!(result.contains("tool=Edit"));
}

#[test]
fn test_format_log_entry_with_glob_tool() {
    let result = format_log_entry("Glob", "allow", "pattern search");
    assert!(result.contains("tool=Glob"));
}

#[test]
fn test_format_log_entry_with_grep_tool() {
    let result = format_log_entry("Grep", "deny", "restricted pattern");
    assert!(result.contains("tool=Grep"));
}

#[test]
fn test_format_log_entry_verdict_allow() {
    let result = format_log_entry("Test", "allow", "allowed");
    assert!(result.contains("verdict=allow"));
}

#[test]
fn test_format_log_entry_verdict_deny() {
    let result = format_log_entry("Test", "deny", "denied");
    assert!(result.contains("verdict=deny"));
}

#[test]
fn test_format_log_entry_with_empty_tool_name() {
    let result = format_log_entry("", "deny", "no tool");
    assert!(result.contains("tool="));
    assert!(result.contains("verdict=deny"));
    assert!(result.contains("reason=no tool"));
}

#[test]
fn test_format_log_entry_with_empty_verdict() {
    let result = format_log_entry("Tool", "", "reason");
    assert!(result.contains("tool=Tool"));
    assert!(result.contains("verdict="));
    assert!(result.contains("reason=reason"));
}

#[test]
fn test_format_log_entry_with_empty_reason() {
    let result = format_log_entry("Tool", "allow", "");
    assert!(result.contains("tool=Tool"));
    assert!(result.contains("verdict=allow"));
    assert!(result.contains("reason="));
}

#[test]
fn test_format_log_entry_all_empty() {
    let result = format_log_entry("", "", "");
    assert!(result.contains("tool="));
    assert!(result.contains("verdict="));
    assert!(result.contains("reason="));
}

#[test]
fn test_format_log_entry_with_unicode_tool_name() {
    let result = format_log_entry("工具", "deny", "test");
    assert!(result.contains("tool=工具"));
}

#[test]
fn test_format_log_entry_with_unicode_reason() {
    let result = format_log_entry("Tool", "deny", "Причина: файл заблокирован");
    assert!(result.contains("reason=Причина: файл заблокирован"));
}

#[test]
fn test_format_log_entry_with_special_chars_in_reason() {
    let reason = "Path=/tmp/file.txt with spaces & special!@#$%";
    let result = format_log_entry("Tool", "deny", reason);
    assert!(result.contains(reason));
}

#[test]
fn test_format_log_entry_with_newlines_in_reason() {
    let reason = "Multi\nline\nreason";
    let result = format_log_entry("Tool", "deny", reason);
    assert!(result.contains(reason));
}

#[test]
fn test_format_log_entry_with_equals_in_reason() {
    let reason = "key=value and another=value";
    let result = format_log_entry("Tool", "deny", reason);
    assert!(result.contains(reason));
}

#[test]
fn test_format_log_entry_with_spaces_in_tool_name() {
    let result = format_log_entry("My Tool", "allow", "test");
    assert!(result.contains("tool=My Tool"));
}

#[test]
fn test_format_log_entry_format_order() {
    let result = format_log_entry("Tool", "deny", "reason");

    let tool_pos = result.find("tool=").unwrap();
    let verdict_pos = result.find("verdict=").unwrap();
    let reason_pos = result.find("reason=").unwrap();

    // Verify order: tool, then verdict, then reason
    assert!(tool_pos < verdict_pos);
    assert!(verdict_pos < reason_pos);
}

#[test]
fn test_format_log_entry_with_very_long_reason() {
    let reason = "x".repeat(5000);
    let result = format_log_entry("Tool", "allow", &reason);
    assert!(result.contains(&reason));
}

