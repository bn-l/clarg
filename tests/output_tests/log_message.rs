use clarg::output::log_message;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// log_message tests
// ============================================================================

#[test]
fn test_log_message_with_none_writes_to_stderr() {
    // This test just verifies it doesn't panic
    log_message(None, "test message");
}

#[test]
fn test_log_message_with_file_path_creates_file() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "test message");

    assert!(log_path.exists());
}

#[test]
fn test_log_message_with_file_path_writes_content() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "test message");

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("test message"));
}

#[test]
fn test_log_message_appends_to_existing_file() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "first message");
    log_message(Some(&log_path), "second message");

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("first message"));
    assert!(content.contains("second message"));
}

#[test]
fn test_log_message_appends_multiple_messages() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "message 1");
    log_message(Some(&log_path), "message 2");
    log_message(Some(&log_path), "message 3");

    let content = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("message 1"));
    assert!(lines[1].contains("message 2"));
    assert!(lines[2].contains("message 3"));
}

#[test]
fn test_log_message_preserves_order() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    for i in 0..10 {
        log_message(Some(&log_path), &format!("message {}", i));
    }

    let content = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    for i in 0..10 {
        assert!(lines[i].contains(&format!("message {}", i)));
    }
}

#[test]
fn test_log_message_with_unicode() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    let message = "Unicode: 你好世界 🚀 Привет";
    log_message(Some(&log_path), message);

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains(message));
}

#[test]
fn test_log_message_with_newlines() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    let message = "Line 1\nLine 2\nLine 3";
    log_message(Some(&log_path), message);

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("Line 1"));
    assert!(content.contains("Line 2"));
    assert!(content.contains("Line 3"));
}

#[test]
fn test_log_message_with_empty_message() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "");

    let content = fs::read_to_string(&log_path).unwrap();
    // Should contain at least a newline
    assert_eq!(content, "\n");
}

#[test]
fn test_log_message_with_empty_message_none_path() {
    // Should not panic
    log_message(None, "");
}

#[test]
fn test_log_message_with_special_characters() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    let message = "Special: !@#$%^&*()_+-=[]{}|;':,.<>?/~`";
    log_message(Some(&log_path), message);

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains(message));
}

#[test]
fn test_log_message_with_very_long_message() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    let message = "a".repeat(100000);
    log_message(Some(&log_path), &message);

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains(&message));
}

#[test]
fn test_log_message_handles_non_writable_path_gracefully() {
    // Use a path that should not be writable (root directory file on Unix)
    let invalid_path = PathBuf::from("/this_should_not_exist_or_be_writable_12345.log");

    // Should not panic
    log_message(Some(&invalid_path), "test");
}

#[test]
fn test_log_message_with_nested_directory() {
    let temp_dir = TempDir::new().unwrap();
    let nested_dir = temp_dir.path().join("nested").join("deep");
    fs::create_dir_all(&nested_dir).unwrap();
    let log_path = nested_dir.join("test.log");

    log_message(Some(&log_path), "nested message");

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains("nested message"));
}

#[test]
fn test_log_message_with_tabs() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    let message = "Column1\tColumn2\tColumn3";
    log_message(Some(&log_path), message);

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.contains(message));
}

#[test]
fn test_log_message_adds_newline() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "message without newline");

    let content = fs::read_to_string(&log_path).unwrap();
    assert!(content.ends_with('\n'));
}

#[test]
fn test_log_message_multiple_calls_separate_lines() {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test.log");

    log_message(Some(&log_path), "line1");
    log_message(Some(&log_path), "line2");

    let content = fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines.len(), 2);
}

