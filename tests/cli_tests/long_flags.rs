use clap::Parser;
use clarg::cli::Cli;

// ============================================================================
// LONG FLAG TESTS: --block-access-to
// ============================================================================

#[test]
fn test_long_flag_block_access_to_single() {
    let args = vec!["clarg", "--block-access-to", ".env"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
}

#[test]
fn test_long_flag_block_access_to_comma_separated() {
    let args = vec!["clarg", "--block-access-to", ".env,*.secret,*.key"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret", "*.key"]);
}

#[test]
fn test_long_flag_block_access_to_multiple_flags() {
    let args = vec!["clarg", "--block-access-to", ".env", "--block-access-to", "*.secret"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
}

#[test]
fn test_long_flag_block_access_to_equals_syntax() {
    let args = vec!["clarg", "--block-access-to=.env,*.secret"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
}

// ============================================================================
// LONG FLAG TESTS: --commands-forbidden
// ============================================================================

#[test]
fn test_long_flag_commands_forbidden_single() {
    let args = vec!["clarg", "--commands-forbidden", "rm"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm"]);
}

#[test]
fn test_long_flag_commands_forbidden_comma_separated() {
    let args = vec!["clarg", "--commands-forbidden", "rm,mv,dd"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv", "dd"]);
}

#[test]
fn test_long_flag_commands_forbidden_multiple_flags() {
    let args = vec!["clarg", "--commands-forbidden", "rm", "--commands-forbidden", "mv"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
}

#[test]
fn test_long_flag_commands_forbidden_equals_syntax() {
    let args = vec!["clarg", "--commands-forbidden=rm,mv"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
}

// ============================================================================
// LONG FLAG TESTS: --log-to
// ============================================================================

#[test]
fn test_long_flag_log_to_simple_path() {
    let args = vec!["clarg", "--log-to", "/tmp/clarg.log"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("/tmp/clarg.log".into()));
}

#[test]
fn test_long_flag_log_to_equals_syntax() {
    let args = vec!["clarg", "--log-to=/tmp/clarg.log"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("/tmp/clarg.log".into()));
}

#[test]
fn test_long_flag_log_to_path_with_spaces() {
    let args = vec!["clarg", "--log-to", "My Documents/logs/clarg.log"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("My Documents/logs/clarg.log".into()));
}

// ============================================================================
// LONG FLAG TESTS: --internal-access-only
// ============================================================================

#[test]
fn test_long_flag_internal_access_only() {
    let args = vec!["clarg", "--internal-access-only"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert!(cli.internal_access_only);
}

#[test]
fn test_long_flag_internal_access_only_is_boolean() {
    let args = vec!["clarg", "--internal-access-only"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.internal_access_only, true);
}
