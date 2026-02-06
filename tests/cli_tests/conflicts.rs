use clap::Parser;
use clarg::cli::Cli;

#[test]
fn test_config_path_conflicts_with_b() {
    let args = vec!["clarg", "config.yaml", "-b", ".env"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_block_access_to() {
    let args = vec!["clarg", "config.yaml", "--block-access-to", ".env"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_c() {
    let args = vec!["clarg", "config.yaml", "-c", "rm"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_commands_forbidden() {
    let args = vec!["clarg", "config.yaml", "--commands-forbidden", "rm"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_l() {
    let args = vec!["clarg", "config.yaml", "-l", "/tmp/log.txt"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_log_to() {
    let args = vec!["clarg", "config.yaml", "--log-to", "/tmp/log.txt"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_i() {
    let args = vec!["clarg", "config.yaml", "-i"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_internal_access_only() {
    let args = vec!["clarg", "config.yaml", "--internal-access-only"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_all_flags() {
    let args = vec![
        "clarg",
        "config.yaml",
        "-b", ".env",
        "-c", "rm",
        "-l", "/tmp/log.txt",
        "-i"
    ];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}

#[test]
fn test_config_path_conflicts_with_multiple_flags_long_form() {
    let args = vec![
        "clarg",
        "config.yaml",
        "--block-access-to", ".env",
        "--commands-forbidden", "rm",
        "--log-to", "/tmp/log.txt",
        "--internal-access-only"
    ];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("conflict") || err.to_string().contains("cannot be used"));
}
