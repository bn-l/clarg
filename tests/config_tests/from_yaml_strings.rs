use clarg::config::Config;
use super::helpers::create_yaml_file;

// ============================================================================
// Config::from_yaml TESTS - Empty Strings & Whitespace
// ============================================================================

#[test]
fn test_from_yaml_empty_strings_in_block_access_to() {
    let yaml = r#"
block_access_to:
  - ".env"
  - ""
  - "*.secret"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 3);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "");
    assert_eq!(config.block_access_to[2], "*.secret");
}

#[test]
fn test_from_yaml_empty_strings_in_commands_forbidden() {
    let yaml = r#"
commands_forbidden:
  - "rm"
  - ""
  - "sudo"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 3);
    assert_eq!(config.commands_forbidden[0], "rm");
    assert_eq!(config.commands_forbidden[1], "");
    assert_eq!(config.commands_forbidden[2], "sudo");
}

#[test]
fn test_from_yaml_patterns_with_leading_spaces() {
    let yaml = r#"
block_access_to:
  - "  .env"
  - "   *.secret"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], "  .env");
    assert_eq!(config.block_access_to[1], "   *.secret");
}

#[test]
fn test_from_yaml_patterns_with_trailing_spaces() {
    let yaml = r#"
block_access_to:
  - ".env  "
  - "*.secret   "
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env  ");
    assert_eq!(config.block_access_to[1], "*.secret   ");
}

#[test]
fn test_from_yaml_patterns_with_tabs() {
    let yaml = r#"
block_access_to:
  - "	.env"
  - "*.secret	"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], "\t.env");
    assert_eq!(config.block_access_to[1], "*.secret\t");
}

// ============================================================================
