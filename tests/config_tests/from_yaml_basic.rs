use clarg::config::Config;
use std::path::PathBuf;
use super::helpers::create_yaml_file;

// ============================================================================
// Config::from_yaml TESTS - Basic Functionality
// ============================================================================

#[test]
fn test_from_yaml_all_fields() {
    let yaml = r#"
block_access_to:
  - ".env"
  - "*.secret"
commands_forbidden:
  - "rm -rf"
  - "sudo"
log_dir: "/tmp/clarg.log"
internal_access_only: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 2);
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.commands_forbidden[1], "sudo");
    assert_eq!(config.log_dir, Some(PathBuf::from("/tmp/clarg.log")));
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_yaml_only_block_access_to() {
    let yaml = r#"
block_access_to:
  - ".env"
  - "*.secret"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_only_commands_forbidden() {
    let yaml = r#"
commands_forbidden:
  - "rm -rf"
  - "sudo"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 2);
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.commands_forbidden[1], "sudo");
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_only_log_dir() {
    let yaml = r#"
log_dir: "/tmp/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, Some(PathBuf::from("/tmp/clarg.log")));
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_only_internal_access_only_true() {
    let yaml = r#"
internal_access_only: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_yaml_only_internal_access_only_false() {
    let yaml = r#"
internal_access_only: false
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_empty_arrays() {
    let yaml = r#"
block_access_to: []
commands_forbidden: []
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_empty_file() {
    let yaml = r#""#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_minimal_valid() {
    let yaml = r#"{}"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_dir, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_yaml_special_flags_defaults_false_when_missing() {
    let yaml = r#"
block_access_to:
  - ".env"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();
    assert_eq!(config.no_root, false);
    assert_eq!(config.no_system_dirs, false);
    assert_eq!(config.no_unknown_tools, false);
}

#[test]
fn test_from_yaml_special_flags_parses_both_true() {
    let yaml = r#"
special_flags:
  no_root: true
  no_system_dirs: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();
    assert_eq!(config.no_root, true);
    assert_eq!(config.no_system_dirs, true);
    assert_eq!(config.no_unknown_tools, false);
}

#[test]
fn test_from_yaml_special_flags_partial_section_defaults_other_flag_false() {
    let yaml = r#"
special_flags:
  no_root: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();
    assert_eq!(config.no_root, true);
    assert_eq!(config.no_system_dirs, false);
    assert_eq!(config.no_unknown_tools, false);
}

#[test]
fn test_from_yaml_all_three_special_flags_true() {
    let yaml = r#"
special_flags:
  no_root: true
  no_system_dirs: true
  no_unknown_tools: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();
    assert_eq!(config.no_root, true);
    assert_eq!(config.no_system_dirs, true);
    assert_eq!(config.no_unknown_tools, true);
}

#[test]
fn test_from_yaml_special_flags_alongside_other_fields() {
    let yaml = r#"
block_access_to:
  - ".env"
commands_forbidden:
  - "rm -rf"
internal_access_only: true
special_flags:
  no_root: true
  no_system_dirs: false
  no_unknown_tools: true
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();
    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.internal_access_only, true);
    assert_eq!(config.no_root, true);
    assert_eq!(config.no_system_dirs, false);
    assert_eq!(config.no_unknown_tools, true);
}

// ============================================================================
