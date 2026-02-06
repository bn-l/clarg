use clarg::config::Config;
use std::path::PathBuf;
use super::helpers::create_yaml_file;

// ============================================================================
// Config::from_yaml TESTS - YAML Comments
// ============================================================================

#[test]
fn test_from_yaml_with_comments() {
    let yaml = r#"
# This is a comment
block_access_to:
  - ".env"  # Protect environment files
  - "*.secret"  # Protect secret files
# Another comment
commands_forbidden:
  - "rm -rf"  # Dangerous command
log_to: "/tmp/clarg.log"  # Log path
internal_access_only: true  # Restrict access
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/clarg.log")));
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_yaml_with_only_comments() {
    let yaml = r#"
# Just a bunch of comments
# No actual config here
# block_access_to:
#   - ".env"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

// ============================================================================
// Config::from_yaml TESTS - YAML Quotes
// ============================================================================

#[test]
fn test_from_yaml_double_quoted_values() {
    let yaml = r#"
block_access_to:
  - ".env"
  - "*.secret"
commands_forbidden:
  - "rm -rf"
log_to: "/tmp/clarg.log"
internal_access_only: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden[0], "rm -rf");
}

#[test]
fn test_from_yaml_single_quoted_values() {
    let yaml = r#"
block_access_to:
  - '.env'
  - '*.secret'
commands_forbidden:
  - 'rm -rf'
log_to: '/tmp/clarg.log'
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/clarg.log")));
}

#[test]
fn test_from_yaml_mixed_quoted_values() {
    let yaml = r#"
block_access_to:
  - ".env"
  - '*.secret'
  - unquoted.txt
commands_forbidden:
  - "rm -rf"
  - 'sudo'
  - dd
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 3);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.block_access_to[2], "unquoted.txt");
    assert_eq!(config.commands_forbidden.len(), 3);
}

#[test]
fn test_from_yaml_escaped_quotes_in_values() {
    let yaml = r#"
block_access_to:
  - "file\"with\"quotes.txt"
commands_forbidden:
  - "echo \"hello\""
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], "file\"with\"quotes.txt");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "echo \"hello\"");
}

// ============================================================================
// Config::from_yaml TESTS - Multiline Strings
// ============================================================================

#[test]
fn test_from_yaml_multiline_literal_strings() {
    let yaml = r#"
commands_forbidden:
  - |
    multiline
    command
    here
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "multiline\ncommand\nhere\n");
}

#[test]
fn test_from_yaml_multiline_folded_strings() {
    let yaml = r#"
commands_forbidden:
  - >
    this is a
    folded string
    that should be
    on one line
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 1);
    assert!(config.commands_forbidden[0].contains("this is a folded string"));
}

// ============================================================================
// Config::from_yaml TESTS - YAML Anchors and Aliases
// ============================================================================

#[test]
fn test_from_yaml_with_anchors_and_aliases() {
    let yaml = r#"
block_access_to: &patterns
  - ".env"
  - "*.secret"
commands_forbidden: *patterns
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 2);
    assert_eq!(config.commands_forbidden[0], ".env");
    assert_eq!(config.commands_forbidden[1], "*.secret");
}

// ============================================================================
// Config::from_yaml TESTS - YAML Edge Cases
// ============================================================================

#[test]
fn test_from_yaml_yaml_special_values() {
    let yaml = r#"
block_access_to:
  - "yes"
  - "no"
  - "true"
  - "false"
  - "on"
  - "off"
  - "null"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 7);
    assert_eq!(config.block_access_to[0], "yes");
    assert_eq!(config.block_access_to[1], "no");
    assert_eq!(config.block_access_to[2], "true");
    assert_eq!(config.block_access_to[3], "false");
    assert_eq!(config.block_access_to[4], "on");
    assert_eq!(config.block_access_to[5], "off");
    assert_eq!(config.block_access_to[6], "null");
}

#[test]
fn test_from_yaml_yaml_numbers_as_strings() {
    let yaml = r#"
block_access_to:
  - "123"
  - "456.789"
  - "0x1F"
  - "1e10"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 4);
    assert_eq!(config.block_access_to[0], "123");
    assert_eq!(config.block_access_to[1], "456.789");
    assert_eq!(config.block_access_to[2], "0x1F");
    assert_eq!(config.block_access_to[3], "1e10");
}

#[test]
fn test_from_yaml_very_long_strings() {
    let long_string = "a".repeat(1000);
    let yaml = format!(
        r#"
block_access_to:
  - "{}"
"#,
        long_string
    );
    let file = create_yaml_file(&yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0].len(), 1000);
    assert_eq!(config.block_access_to[0], long_string);
}

#[test]
fn test_from_yaml_special_characters_in_patterns() {
    let yaml = r#"
block_access_to:
  - "file@#$%.txt"
  - "file&*().md"
  - "file|<>.rs"
  - "file;:`~.yaml"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 4);
    assert_eq!(config.block_access_to[0], "file@#$%.txt");
    assert_eq!(config.block_access_to[1], "file&*().md");
    assert_eq!(config.block_access_to[2], "file|<>.rs");
    assert_eq!(config.block_access_to[3], "file;:`~.yaml");
}

#[test]
fn test_from_yaml_backslashes_in_patterns() {
    let yaml = r#"
block_access_to:
  - "C:\\Users\\Admin\\file.txt"
  - "\\\\network\\share\\file.txt"
commands_forbidden:
  - "echo \\n\\t\\r"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], "C:\\Users\\Admin\\file.txt");
    assert_eq!(config.block_access_to[1], "\\\\network\\share\\file.txt");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "echo \\n\\t\\r");
}

#[test]
fn test_from_yaml_newlines_in_patterns() {
    let yaml = "block_access_to:\n  - \"line1\\nline2\"\n";
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    // YAML interprets \n as an actual newline, not escaped string
    assert_eq!(config.block_access_to[0], "line1\nline2");
}

#[test]
fn test_from_yaml_flow_style_arrays() {
    let yaml = r#"
block_access_to: [".env", "*.secret"]
commands_forbidden: ["rm -rf", "sudo"]
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 2);
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.commands_forbidden[1], "sudo");
}

#[test]
fn test_from_yaml_flow_style_complete() {
    let yaml = r#"{block_access_to: [".env"], commands_forbidden: ["rm"], log_to: "/tmp/log", internal_access_only: true}"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "rm");
    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/log")));
    assert_eq!(config.internal_access_only, true);
}

// ============================================================================
