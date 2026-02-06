use clap::Parser;
use clarg::cli::Cli;

// ============================================================================
// SHORT FLAG TESTS: -b
// ============================================================================

#[test]
fn test_short_flag_b_single_pattern() {
    let args = vec!["clarg", "-b", ".env"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env"]);
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.log_to.is_none());
    assert!(!cli.internal_access_only);
}

#[test]
fn test_short_flag_b_comma_separated_two_items() {
    let args = vec!["clarg", "-b", ".env,*.secret"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
}

#[test]
fn test_short_flag_b_comma_separated_multiple_items() {
    let args = vec!["clarg", "-b", ".env,*.secret,*.key,secrets/"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret", "*.key", "secrets/"]);
}

#[test]
fn test_short_flag_b_multiple_flags() {
    let args = vec!["clarg", "-b", ".env", "-b", "*.secret"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret"]);
}

#[test]
fn test_short_flag_b_multiple_flags_three_items() {
    let args = vec!["clarg", "-b", ".env", "-b", "*.secret", "-b", "*.key"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret", "*.key"]);
}

#[test]
fn test_short_flag_b_mixed_comma_and_multiple_flags() {
    let args = vec!["clarg", "-b", ".env,*.secret", "-b", "*.key"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", "*.secret", "*.key"]);
}

#[test]
fn test_short_flag_b_glob_patterns() {
    let args = vec!["clarg", "-b", "**/*.env,**/secrets/**,tmp/*"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["**/*.env", "**/secrets/**", "tmp/*"]);
}

#[test]
fn test_short_flag_b_patterns_with_dots() {
    let args = vec!["clarg", "-b", ".env,.git,.ssh,.config"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env", ".git", ".ssh", ".config"]);
}

#[test]
fn test_short_flag_b_patterns_with_slashes() {
    let args = vec!["clarg", "-b", "secrets/,/etc/passwd,~/.ssh/"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["secrets/", "/etc/passwd", "~/.ssh/"]);
}

#[test]
fn test_short_flag_b_empty_string() {
    let args = vec!["clarg", "-b", ""];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![""]);
}

#[test]
fn test_short_flag_b_pattern_with_spaces_quoted() {
    let args = vec!["clarg", "-b", "My Documents/*.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["My Documents/*.txt"]);
}

#[test]
fn test_short_flag_b_special_characters() {
    let args = vec!["clarg", "-b", "*.{env,secret},file[0-9].txt,data?.db"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Note: Comma delimiter splits on all commas, including those inside braces
    assert_eq!(cli.block_access_to, vec!["*.{env", "secret}", "file[0-9].txt", "data?.db"]);
}

// ============================================================================
// SHORT FLAG TESTS: -c
// ============================================================================

#[test]
fn test_short_flag_c_single_command() {
    let args = vec!["clarg", "-c", "rm"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm"]);
    assert!(cli.block_access_to.is_empty());
}

#[test]
fn test_short_flag_c_comma_separated_two_items() {
    let args = vec!["clarg", "-c", "rm,mv"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
}

#[test]
fn test_short_flag_c_comma_separated_multiple_items() {
    let args = vec!["clarg", "-c", "rm,mv,dd,mkfs"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv", "dd", "mkfs"]);
}

#[test]
fn test_short_flag_c_multiple_flags() {
    let args = vec!["clarg", "-c", "rm", "-c", "mv"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv"]);
}

#[test]
fn test_short_flag_c_multiple_flags_three_items() {
    let args = vec!["clarg", "-c", "rm", "-c", "mv", "-c", "dd"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv", "dd"]);
}

#[test]
fn test_short_flag_c_mixed_comma_and_multiple_flags() {
    let args = vec!["clarg", "-c", "rm,mv", "-c", "dd"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm", "mv", "dd"]);
}

#[test]
fn test_short_flag_c_regex_patterns() {
    let args = vec!["clarg", "-c", "^rm.*,.*--force,dd.*if="];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["^rm.*", ".*--force", "dd.*if="]);
}

#[test]
fn test_short_flag_c_patterns_with_special_chars() {
    let args = vec!["clarg", "-c", r"rm\s+-rf,curl.*\|\s*sh,wget.*&&"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec![r"rm\s+-rf", r"curl.*\|\s*sh", r"wget.*&&"]);
}

#[test]
fn test_short_flag_c_empty_string() {
    let args = vec!["clarg", "-c", ""];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec![""]);
}

#[test]
fn test_short_flag_c_command_with_spaces_quoted() {
    let args = vec!["clarg", "-c", "rm -rf /"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["rm -rf /"]);
}

// ============================================================================
// SHORT FLAG TESTS: -l
// ============================================================================

#[test]
fn test_short_flag_l_simple_path() {
    let args = vec!["clarg", "-l", "/tmp/clarg.log"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("/tmp/clarg.log".into()));
}

#[test]
fn test_short_flag_l_relative_path() {
    let args = vec!["clarg", "-l", "logs/output.log"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("logs/output.log".into()));
}

#[test]
fn test_short_flag_l_path_with_spaces() {
    let args = vec!["clarg", "-l", "my logs/output.log"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("my logs/output.log".into()));
}

#[test]
fn test_short_flag_l_path_with_tilde() {
    let args = vec!["clarg", "-l", "~/.config/clarg/log.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("~/.config/clarg/log.txt".into()));
}

#[test]
fn test_short_flag_l_very_long_path() {
    let long_path = "/very/long/path/that/goes/deep/into/the/filesystem/hierarchy/with/many/segments/and/subdirectories/log.txt";
    let args = vec!["clarg", "-l", long_path];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some(long_path.into()));
}

// ============================================================================
// SHORT FLAG TESTS: -i
// ============================================================================

#[test]
fn test_short_flag_i_alone() {
    let args = vec!["clarg", "-i"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert!(cli.internal_access_only);
    assert!(cli.block_access_to.is_empty());
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.log_to.is_none());
}

#[test]
fn test_short_flag_i_is_boolean() {
    let args = vec!["clarg", "-i"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.internal_access_only, true);
}
