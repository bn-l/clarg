use clap::Parser;
use clarg::cli::Cli;

// ============================================================================
// COMBINATION TESTS (all flags together, no config)
// ============================================================================

#[test]
fn test_all_flags_combined_short() {
    let args = vec![
        "clarg",
        "-b", ".env",
        "-c", "rm",
        "-l", "/tmp/log.txt",
        "-i"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
    assert!(cli.config_path.is_none());
}

#[test]
fn test_all_flags_combined_long() {
    let args = vec![
        "clarg",
        "--block-access-to", ".env",
        "--commands-forbidden", "rm",
        "--log-to", "/tmp/log.txt",
        "--internal-access-only"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
    assert!(cli.config_path.is_none());
}

#[test]
fn test_all_flags_combined_mixed_short_long() {
    let args = vec![
        "clarg",
        "-b", ".env,*.secret",
        "--commands-forbidden", "rm,mv",
        "-l", "/tmp/log.txt",
        "--internal-access-only"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
}

#[test]
fn test_all_flags_combined_multiple_values() {
    let args = vec![
        "clarg",
        "-b", ".env", "-b", "*.secret", "-b", "*.key",
        "-c", "rm", "-c", "mv", "-c", "dd",
        "-l", "/var/log/clarg.log",
        "-i"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret", "*.key"]);
    assert_eq!(cli.commands_forbidden, vec!["rm", "mv", "dd"]);
    assert_eq!(cli.log_to, Some("/var/log/clarg.log".into()));
    assert!(cli.internal_access_only);
}

#[test]
fn test_all_flags_complex_patterns() {
    let args = vec![
        "clarg",
        "-b", "**/*.env,**/secrets/**,.git,.ssh",
        "-c", r"^rm\s+-rf,curl.*\|\s*sh,dd.*if=",
        "-l", "~/.config/clarg/logs/output.log",
        "-i"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["**/*.env", "**/secrets/**", ".git", ".ssh"]);
    assert_eq!(cli.commands_forbidden, vec![r"^rm\s+-rf", r"curl.*\|\s*sh", r"dd.*if="]);
    assert_eq!(cli.log_to, Some("~/.config/clarg/logs/output.log".into()));
    assert!(cli.internal_access_only);
}

#[test]
fn test_flags_in_different_order() {
    let args = vec![
        "clarg",
        "-i",
        "-l", "/tmp/log.txt",
        "-c", "rm",
        "-b", ".env"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
}

#[test]
fn test_flags_interleaved() {
    let args = vec![
        "clarg",
        "-b", ".env",
        "-c", "rm",
        "-b", "*.secret",
        "-c", "mv",
        "-l", "/tmp/log.txt"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
}

#[test]
fn test_mixed_short_and_long_flags() {
    let args = vec![
        "clarg",
        "-b", ".env",
        "--commands-forbidden", "rm",
        "-l", "/tmp/log.txt",
        "--internal-access-only"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
}

#[test]
fn test_equals_syntax_for_all_long_flags() {
    let args = vec![
        "clarg",
        "--block-access-to=.env,*.secret",
        "--commands-forbidden=rm,mv",
        "--log-to=/tmp/log.txt",
        "--internal-access-only"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
}

#[test]
fn test_only_i_flag_with_everything_else_default() {
    let args = vec!["clarg", "-i"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert!(cli.internal_access_only);
    assert!(cli.block_access_to.is_empty());
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.log_to.is_none());
    assert!(cli.config_path.is_none());
}

#[test]
fn test_only_l_flag_with_everything_else_default() {
    let args = vec!["clarg", "-l", "/tmp/log.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.block_access_to.is_empty());
    assert!(cli.commands_forbidden.is_empty());
    assert!(!cli.internal_access_only);
    assert!(cli.config_path.is_none());
}

#[test]
fn test_b_and_c_combined_only() {
    let args = vec!["clarg", "-b", ".env", "-c", "rm"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert!(cli.log_to.is_none());
    assert!(!cli.internal_access_only);
    assert!(cli.config_path.is_none());
}

#[test]
fn test_b_and_i_combined_only() {
    let args = vec!["clarg", "-b", ".env", "-i"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert!(cli.internal_access_only);
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.log_to.is_none());
    assert!(cli.config_path.is_none());
}

#[test]
fn test_c_and_i_combined_only() {
    let args = vec!["clarg", "-c", "rm", "-i"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert!(cli.internal_access_only);
    assert!(cli.block_access_to.is_empty());
    assert!(cli.log_to.is_none());
    assert!(cli.config_path.is_none());
}

#[test]
fn test_l_and_i_combined_only() {
    let args = vec!["clarg", "-l", "/tmp/log.txt", "-i"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(cli.internal_access_only);
    assert!(cli.block_access_to.is_empty());
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.config_path.is_none());
}

#[test]
fn test_b_c_and_l_combined_no_i() {
    let args = vec!["clarg", "-b", ".env", "-c", "rm", "-l", "/tmp/log.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert_eq!(cli.log_to, Some("/tmp/log.txt".into()));
    assert!(!cli.internal_access_only);
    assert!(cli.config_path.is_none());
}
