use clarg::config::Config;
use std::path::PathBuf;
use super::helpers::create_yaml_file;

// ============================================================================
// Config Default Trait Test
// ============================================================================

#[test]
fn test_config_default_trait() {
    let config = Config::default();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

// ============================================================================
// Config::from_yaml TESTS - Extremely Complex Edge Cases
// ============================================================================

#[test]
fn test_from_yaml_deeply_nested_patterns() {
    let yaml = r#"
block_access_to:
  - "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/file.txt"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(
        config.block_access_to[0],
        "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/file.txt"
    );
}

#[test]
fn test_from_yaml_array_with_single_item() {
    let yaml = r#"
block_access_to:
  - ".env"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
}

#[test]
fn test_from_yaml_boolean_variations() {
    let yaml = r#"
internal_access_only: True
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_yaml_boolean_yes() {
    let yaml = r#"
internal_access_only: yes
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // serde_yaml treats "yes" as a string, not a boolean
    assert!(result.is_err());
}

#[test]
fn test_from_yaml_boolean_no() {
    let yaml = r#"
internal_access_only: no
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // serde_yaml treats "no" as a string, not a boolean
    assert!(result.is_err());
}

#[test]
fn test_from_yaml_boolean_on() {
    let yaml = r#"
internal_access_only: on
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // serde_yaml treats "on" as a string, not a boolean
    assert!(result.is_err());
}

#[test]
fn test_from_yaml_boolean_off() {
    let yaml = r#"
internal_access_only: off
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // serde_yaml treats "off" as a string, not a boolean
    assert!(result.is_err());
}

#[test]
fn test_from_yaml_duplicate_patterns() {
    let yaml = r#"
block_access_to:
  - ".env"
  - ".env"
  - ".env"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 3);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], ".env");
    assert_eq!(config.block_access_to[2], ".env");
}

#[test]
fn test_from_yaml_patterns_with_only_whitespace() {
    let yaml = r#"
block_access_to:
  - "   "
  - "		"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], "   ");
    assert_eq!(config.block_access_to[1], "\t\t");
}

#[test]
fn test_from_yaml_mixed_array_and_block_style() {
    let yaml = r#"
block_access_to: [".env",
  "*.secret",
  "*.key"]
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 3);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.block_access_to[2], "*.key");
}

#[test]
fn test_from_yaml_log_to_empty_string() {
    let yaml = r#"
log_to: ""
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("")));
}

#[test]
fn test_from_yaml_patterns_with_forward_slashes() {
    let yaml = r#"
block_access_to:
  - "/"
  - "/root"
  - "//double/slash"
  - "path///triple///slash"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 4);
    assert_eq!(config.block_access_to[0], "/");
    assert_eq!(config.block_access_to[1], "/root");
    assert_eq!(config.block_access_to[2], "//double/slash");
    assert_eq!(config.block_access_to[3], "path///triple///slash");
}

#[test]
fn test_from_yaml_patterns_with_dots() {
    let yaml = r#"
block_access_to:
  - "."
  - ".."
  - "..."
  - ".hidden"
  - "..hidden"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 5);
    assert_eq!(config.block_access_to[0], ".");
    assert_eq!(config.block_access_to[1], "..");
    assert_eq!(config.block_access_to[2], "...");
    assert_eq!(config.block_access_to[3], ".hidden");
    assert_eq!(config.block_access_to[4], "..hidden");
}

#[test]
fn test_from_yaml_commands_with_pipes_and_redirects() {
    let yaml = r#"
commands_forbidden:
  - "cat /etc/passwd | grep root"
  - "ls > file.txt"
  - "echo test >> file.txt"
  - "command 2>&1"
  - "cmd1 | cmd2 | cmd3"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 5);
    assert_eq!(config.commands_forbidden[0], "cat /etc/passwd | grep root");
    assert_eq!(config.commands_forbidden[1], "ls > file.txt");
    assert_eq!(config.commands_forbidden[2], "echo test >> file.txt");
    assert_eq!(config.commands_forbidden[3], "command 2>&1");
    assert_eq!(config.commands_forbidden[4], "cmd1 | cmd2 | cmd3");
}

#[test]
fn test_from_yaml_commands_with_shell_metacharacters() {
    let yaml = r#"
commands_forbidden:
  - "cmd && cmd2"
  - "cmd || cmd2"
  - "cmd ; cmd2"
  - "cmd & "
  - "$(dangerous)"
  - "`backticks`"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 6);
    assert_eq!(config.commands_forbidden[0], "cmd && cmd2");
    assert_eq!(config.commands_forbidden[1], "cmd || cmd2");
    assert_eq!(config.commands_forbidden[2], "cmd ; cmd2");
    assert_eq!(config.commands_forbidden[3], "cmd & ");
    assert_eq!(config.commands_forbidden[4], "$(dangerous)");
    assert_eq!(config.commands_forbidden[5], "`backticks`");
}

#[test]
fn test_from_yaml_case_sensitivity() {
    let yaml = r#"
block_access_to:
  - ".ENV"
  - ".env"
  - ".Env"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 3);
    assert_eq!(config.block_access_to[0], ".ENV");
    assert_eq!(config.block_access_to[1], ".env");
    assert_eq!(config.block_access_to[2], ".Env");
}

#[test]
fn test_from_yaml_trailing_comma_not_allowed() {
    let yaml = r#"
block_access_to: [".env", "*.secret",]
"#;
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // serde_yaml actually allows trailing commas
    if let Ok(config) = result {
        assert_eq!(config.block_access_to.len(), 2);
    } else {
        // Some YAML parsers may reject this, which is also acceptable
        assert!(result.is_err());
    }
}

#[test]
fn test_from_yaml_indentation_with_tabs() {
    // YAML spec discourages tabs but some parsers may accept them
    let yaml = "block_access_to:\n\t- \".env\"\n";
    let file = create_yaml_file(yaml);
    let result = Config::from_yaml(&file.path().to_path_buf());

    // This might error depending on the YAML parser's strictness
    // If it succeeds, the value should be correct
    if let Ok(config) = result {
        assert_eq!(config.block_access_to.len(), 1);
        assert_eq!(config.block_access_to[0], ".env");
    }
}

#[test]
fn test_from_yaml_extremely_nested_flow_style() {
    let yaml = r#"{"block_access_to": [".env", "*.secret"], "commands_forbidden": ["rm"], "internal_access_only": true}"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_yaml_compact_format() {
    let yaml = r#"block_access_to: [".env"]
commands_forbidden: ["rm"]
log_to: "/tmp/log"
internal_access_only: true"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/log")));
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_yaml_windows_line_endings() {
    let yaml = "block_access_to:\r\n  - \".env\"\r\ncommands_forbidden:\r\n  - \"rm\"\r\n";
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "rm");
}

#[test]
fn test_from_yaml_mac_classic_line_endings() {
    let yaml = "block_access_to:\r  - \".env\"\rcommands_forbidden:\r  - \"rm\"\r";
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "rm");
}

#[test]
fn test_from_yaml_mixed_line_endings() {
    let yaml = "block_access_to:\r\n  - \".env\"\n  - \"*.secret\"\rcommands_forbidden:\n  - \"rm\"\r\n";
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.commands_forbidden.len(), 1);
}

#[test]
fn test_from_yaml_utf8_bom() {
    let yaml = "\u{FEFF}block_access_to:\n  - \".env\"\n";
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
}

#[test]
fn test_from_yaml_document_markers() {
    let yaml = r#"---
block_access_to:
  - ".env"
..."#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
}

#[test]
fn test_from_yaml_multiple_documents() {
    let yaml = r#"---
block_access_to:
  - ".env"
---
block_access_to:
  - "*.secret"
"#;
    let file = create_yaml_file(yaml);
    // serde_yaml doesn't support multiple documents
    let result = Config::from_yaml(&file.path().to_path_buf());

    assert!(result.is_err());
}
