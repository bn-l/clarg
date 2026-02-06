use clarg::cli::Cli;
use clarg::config::Config;
use std::path::PathBuf;
use super::helpers::{create_cli_no_flags, create_cli_all_flags, create_cli_partial_flags, create_yaml_file};

// ============================================================================
// Config::from_cli TESTS
// ============================================================================

#[test]
fn test_from_cli_no_flags() {
    let cli = create_cli_no_flags();
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_cli_all_flags_populated() {
    let cli = create_cli_all_flags();
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 2);
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.commands_forbidden[1], "sudo");
    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/clarg.log")));
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_cli_partial_flags() {
    let cli = create_cli_partial_flags();
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 1);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_cli_only_block_access_to() {
    let cli = Cli {
        config_path: None,
        block_access_to: vec!["*.pem".to_string(), "*.key".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], "*.pem");
    assert_eq!(config.block_access_to[1], "*.key");
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_cli_only_commands_forbidden() {
    let cli = Cli {
        config_path: None,
        block_access_to: vec![],
        commands_forbidden: vec!["dd".to_string(), "mkfs".to_string()],
        log_to: None,
        internal_access_only: false,
    };
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 2);
    assert_eq!(config.commands_forbidden[0], "dd");
    assert_eq!(config.commands_forbidden[1], "mkfs");
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_cli_only_log_to() {
    let cli = Cli {
        config_path: None,
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: Some(PathBuf::from("/var/log/clarg.log")),
        internal_access_only: false,
    };
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, Some(PathBuf::from("/var/log/clarg.log")));
    assert_eq!(config.internal_access_only, false);
}

#[test]
fn test_from_cli_only_internal_access_only() {
    let cli = Cli {
        config_path: None,
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: true,
    };
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 0);
    assert_eq!(config.commands_forbidden.len(), 0);
    assert_eq!(config.log_to, None);
    assert_eq!(config.internal_access_only, true);
}

#[test]
fn test_from_cli_with_config_path() {
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
    let cli = Cli {
        config_path: Some(file.path().to_path_buf()),
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    };
    let config = Config::from_cli(cli).unwrap();

    assert_eq!(config.block_access_to.len(), 2);
    assert_eq!(config.block_access_to[0], ".env");
    assert_eq!(config.block_access_to[1], "*.secret");
    assert_eq!(config.commands_forbidden.len(), 1);
    assert_eq!(config.commands_forbidden[0], "rm -rf");
    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/clarg.log")));
    assert_eq!(config.internal_access_only, true);
}

// ============================================================================
