use clap::Parser;
use clarg::cli::Cli;

// ============================================================================
// EDGE CASE TESTS: Large lists
// ============================================================================

#[test]
fn test_b_flag_with_many_comma_separated_items() {
    let args = vec![
        "clarg",
        "-b",
        ".env,.git,.ssh,.config,*.secret,*.key,*.pem,secrets/,private/,~/.*"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(
        cli.block_access_to,
        vec![".env", ".git", ".ssh", ".config", "*.secret", "*.key", "*.pem", "secrets/", "private/", "~/.*"]
    );
}

#[test]
fn test_c_flag_with_many_comma_separated_items() {
    let args = vec![
        "clarg",
        "-c",
        "rm,mv,dd,mkfs,fdisk,parted,systemctl,shutdown,reboot"
    ];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(
        cli.commands_forbidden,
        vec!["rm", "mv", "dd", "mkfs", "fdisk", "parted", "systemctl", "shutdown", "reboot"]
    );
}

#[test]
fn test_extremely_long_pattern_list() {
    let pattern = (0..100).map(|i| format!("pattern{}", i)).collect::<Vec<_>>().join(",");
    let args = vec!["clarg", "-b", &pattern];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to.len(), 100);
    assert_eq!(cli.block_access_to[0], "pattern0");
    assert_eq!(cli.block_access_to[99], "pattern99");
}

// ============================================================================
// EDGE CASE TESTS: Glob patterns with special characters
// ============================================================================

#[test]
fn test_b_flag_glob_with_curly_braces() {
    let args = vec!["clarg", "-b", "*.{env,secret,key,pem}"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Note: Comma delimiter splits on all commas, including those inside braces
    assert_eq!(cli.block_access_to, vec!["*.{env", "secret", "key", "pem}"]);
}

#[test]
fn test_b_flag_glob_with_curly_braces_using_multiple_flags() {
    // To preserve curly braces with commas, use multiple -b flags
    let args = vec!["clarg", "-b", "*.{env,secret,key,pem}", "-b", "file.{txt,md}"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Still gets split because each flag value is split by comma delimiter
    assert_eq!(cli.block_access_to, vec!["*.{env", "secret", "key", "pem}", "file.{txt", "md}"]);
}

#[test]
fn test_b_flag_glob_with_square_brackets() {
    let args = vec!["clarg", "-b", "file[0-9].txt,data[a-z].db"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file[0-9].txt", "data[a-z].db"]);
}

#[test]
fn test_b_flag_glob_with_question_mark() {
    let args = vec!["clarg", "-b", "data?.db,file?.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["data?.db", "file?.txt"]);
}

#[test]
fn test_b_flag_negation_pattern() {
    let args = vec!["clarg", "-b", "!important.txt,*.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["!important.txt", "*.txt"]);
}

// ============================================================================
// EDGE CASE TESTS: Regex patterns
// ============================================================================

#[test]
fn test_c_flag_regex_with_anchors() {
    let args = vec!["clarg", "-c", "^rm$,^sudo.*,.*--force$"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["^rm$", "^sudo.*", ".*--force$"]);
}

#[test]
fn test_c_flag_regex_with_character_classes() {
    let args = vec!["clarg", "-c", r"\brm\b,\bsudo\b,\d+"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec![r"\brm\b", r"\bsudo\b", r"\d+"]);
}

#[test]
fn test_c_flag_regex_with_escape_sequences() {
    let args = vec!["clarg", "-c", r"rm\s+.*,curl.*\|.*,wget.*>.*"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec![r"rm\s+.*", r"curl.*\|.*", r"wget.*>.*"]);
}

#[test]
fn test_c_flag_regex_with_groups() {
    let args = vec!["clarg", "-c", r"(rm|mv|cp)\s+-rf,sudo\s+(rm|dd)"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec![r"(rm|mv|cp)\s+-rf", r"sudo\s+(rm|dd)"]);
}

// ============================================================================
// EDGE CASE TESTS: Path types
// ============================================================================

#[test]
fn test_b_flag_with_absolute_paths() {
    let args = vec!["clarg", "-b", "/etc/passwd,/etc/shadow,/root/.ssh/"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["/etc/passwd", "/etc/shadow", "/root/.ssh/"]);
}

#[test]
fn test_b_flag_with_relative_paths() {
    let args = vec!["clarg", "-b", "./secrets/,../config/,.env"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["./secrets/", "../config/", ".env"]);
}

#[test]
fn test_b_flag_with_home_directory_paths() {
    let args = vec!["clarg", "-b", "~/.ssh/,~/.aws/,~/.config/"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["~/.ssh/", "~/.aws/", "~/.config/"]);
}

#[test]
fn test_b_flag_patterns_with_backslashes() {
    let args = vec!["clarg", "-b", r"C:\Windows\System32,\\network\share"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![r"C:\Windows\System32", r"\\network\share"]);
}

// ============================================================================
// EDGE CASE TESTS: Unicode
// ============================================================================

#[test]
fn test_b_flag_unicode_patterns() {
    let args = vec!["clarg", "-b", "fichier™.txt,文档.doc,файл.pdf"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["fichier™.txt", "文档.doc", "файл.pdf"]);
}

#[test]
fn test_c_flag_unicode_patterns() {
    let args = vec!["clarg", "-c", "删除,удалить,supprimerå"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["删除", "удалить", "supprimerå"]);
}

#[test]
fn test_log_path_unicode() {
    let args = vec!["clarg", "-l", "/tmp/日志/клагー/log™.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some("/tmp/日志/клагー/log™.txt".into()));
}

// ============================================================================
// EDGE CASE TESTS: Comma edge cases
// ============================================================================

#[test]
fn test_single_comma() {
    let args = vec!["clarg", "-b", ","];
    let cli = Cli::try_parse_from(args).unwrap();

    // Comma delimiter with nothing around it produces two empty strings
    assert_eq!(cli.block_access_to, vec!["", ""]);
}

#[test]
fn test_multiple_commas() {
    let args = vec!["clarg", "-b", ",,,"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Multiple commas produce multiple empty strings
    assert_eq!(cli.block_access_to, vec!["", "", "", ""]);
}

#[test]
fn test_trailing_comma() {
    let args = vec!["clarg", "-b", ".env,*.secret,"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Trailing comma produces an empty string at the end
    assert_eq!(cli.block_access_to, vec![".env", "*.secret", ""]);
}

#[test]
fn test_leading_comma() {
    let args = vec!["clarg", "-b", ",.env,*.secret"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Leading comma produces an empty string at the start
    assert_eq!(cli.block_access_to, vec!["", ".env", "*.secret"]);
}

#[test]
fn test_b_and_c_both_empty_strings() {
    let args = vec!["clarg", "-b", "", "-c", ""];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![""]);
    assert_eq!(cli.commands_forbidden, vec![""]);
}

// ============================================================================
// EDGE CASE TESTS: Unknown flags
// ============================================================================

#[test]
fn test_unknown_short_flag() {
    let args = vec!["clarg", "-x"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn test_unknown_long_flag() {
    let args = vec!["clarg", "--unknown-flag"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn test_misspelled_long_flag() {
    let args = vec!["clarg", "--block-access"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// ============================================================================
// EDGE CASE TESTS: Missing values
// ============================================================================

#[test]
fn test_b_flag_missing_value() {
    let args = vec!["clarg", "-b"];
    let result = Cli::try_parse_from(args);

    // -b requires a value
    assert!(result.is_err());
}

#[test]
fn test_c_flag_missing_value() {
    let args = vec!["clarg", "-c"];
    let result = Cli::try_parse_from(args);

    // -c requires a value
    assert!(result.is_err());
}

#[test]
fn test_l_flag_missing_value() {
    let args = vec!["clarg", "-l"];
    let result = Cli::try_parse_from(args);

    // -l requires a value
    assert!(result.is_err());
}

#[test]
fn test_block_access_to_missing_value() {
    let args = vec!["clarg", "--block-access-to"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
}

#[test]
fn test_commands_forbidden_missing_value() {
    let args = vec!["clarg", "--commands-forbidden"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
}

#[test]
fn test_log_to_missing_value() {
    let args = vec!["clarg", "--log-to"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
}

// ============================================================================
// EDGE CASE TESTS: Double dash separator
// ============================================================================

#[test]
fn test_double_dash_before_config_path() {
    let args = vec!["clarg", "--", "config.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("config.yaml".into()));
}

#[test]
fn test_double_dash_before_flag_like_config_path() {
    // After --, everything is treated as positional
    let args = vec!["clarg", "--", "-b"];
    let cli = Cli::try_parse_from(args).unwrap();

    // "-b" is treated as a config path, not a flag
    assert_eq!(cli.config_path, Some("-b".into()));
}

#[test]
fn test_double_dash_with_flags_before() {
    let args = vec!["clarg", "-i", "--", "config.yaml"];
    let result = Cli::try_parse_from(args);

    // config.yaml conflicts with -i
    assert!(result.is_err());
}

// ============================================================================
// EDGE CASE TESTS: Whitespace handling
// ============================================================================

#[test]
fn test_b_flag_value_with_leading_space() {
    let args = vec!["clarg", "-b", " .env"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![" .env"]);
}

#[test]
fn test_b_flag_value_with_trailing_space() {
    let args = vec!["clarg", "-b", ".env "];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".env "]);
}

#[test]
fn test_b_flag_value_with_internal_spaces() {
    let args = vec!["clarg", "-b", "my file.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["my file.txt"]);
}

#[test]
fn test_b_flag_comma_separated_with_spaces_around_comma() {
    let args = vec!["clarg", "-b", ".env , *.secret"];
    let cli = Cli::try_parse_from(args).unwrap();

    // Spaces are preserved
    assert_eq!(cli.block_access_to, vec![".env ", " *.secret"]);
}

// ============================================================================
// EDGE CASE TESTS: Special path patterns
// ============================================================================

#[test]
fn test_b_flag_double_star_pattern() {
    let args = vec!["clarg", "-b", "**/secret/**"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["**/secret/**"]);
}

#[test]
fn test_b_flag_dot_files() {
    let args = vec!["clarg", "-b", ".*"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".*"]);
}

#[test]
fn test_b_flag_current_directory() {
    let args = vec!["clarg", "-b", "."];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["."]);
}

#[test]
fn test_b_flag_parent_directory() {
    let args = vec!["clarg", "-b", ".."];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![".."]);
}

#[test]
fn test_b_flag_root_directory() {
    let args = vec!["clarg", "-b", "/"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["/"]);
}

// ============================================================================
// EDGE CASE TESTS: Multiple positional arguments
// ============================================================================

#[test]
fn test_multiple_positional_arguments_error() {
    let args = vec!["clarg", "config1.yaml", "config2.yaml"];
    let result = Cli::try_parse_from(args);

    // Only one positional argument (config path) is allowed
    assert!(result.is_err());
}

// ============================================================================
// EDGE CASE TESTS: Equals syntax edge cases
// ============================================================================

#[test]
fn test_equals_with_empty_value() {
    let args = vec!["clarg", "--block-access-to="];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec![""]);
}

#[test]
fn test_equals_with_equals_in_value() {
    let args = vec!["clarg", "--block-access-to=file=name.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file=name.txt"]);
}

#[test]
fn test_equals_with_comma_in_value() {
    let args = vec!["clarg", "--block-access-to=a,b,c"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["a", "b", "c"]);
}

// ============================================================================
// EDGE CASE TESTS: Very long values
// ============================================================================

#[test]
fn test_very_long_single_pattern() {
    let long_pattern = "a".repeat(10000);
    let args = vec!["clarg", "-b", &long_pattern];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to.len(), 1);
    assert_eq!(cli.block_access_to[0].len(), 10000);
}

#[test]
fn test_very_long_log_path() {
    let long_path = format!("/{}", "very/long/path/".repeat(100));
    let args = vec!["clarg", "-l", &long_path];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.log_to, Some(long_path.into()));
}

// ============================================================================
// EDGE CASE TESTS: Numeric patterns
// ============================================================================

#[test]
fn test_b_flag_numeric_pattern() {
    let args = vec!["clarg", "-b", "12345"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["12345"]);
}

#[test]
fn test_c_flag_numeric_pattern() {
    let args = vec!["clarg", "-c", "123,456,789"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["123", "456", "789"]);
}

// ============================================================================
// EDGE CASE TESTS: Special characters in patterns
// ============================================================================

#[test]
fn test_b_flag_pattern_with_pipe() {
    let args = vec!["clarg", "-b", "file|backup"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file|backup"]);
}

#[test]
fn test_b_flag_pattern_with_ampersand() {
    let args = vec!["clarg", "-b", "file&backup"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file&backup"]);
}

#[test]
fn test_b_flag_pattern_with_semicolon() {
    let args = vec!["clarg", "-b", "file;backup"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file;backup"]);
}

#[test]
fn test_b_flag_pattern_with_dollar() {
    let args = vec!["clarg", "-b", "$HOME/.env"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["$HOME/.env"]);
}

#[test]
fn test_b_flag_pattern_with_parentheses() {
    let args = vec!["clarg", "-b", "file(1).txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file(1).txt"]);
}

#[test]
fn test_c_flag_pattern_with_quotes() {
    let args = vec!["clarg", "-c", r#"echo "hello""#];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec![r#"echo "hello""#]);
}

#[test]
fn test_c_flag_pattern_with_single_quotes() {
    let args = vec!["clarg", "-c", "echo 'hello'"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["echo 'hello'"]);
}

#[test]
fn test_c_flag_pattern_with_backticks() {
    let args = vec!["clarg", "-c", "echo `whoami`"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.commands_forbidden, vec!["echo `whoami`"]);
}

// ============================================================================
// EDGE CASE TESTS: Tab and newline characters
// ============================================================================

#[test]
fn test_b_flag_pattern_with_tab() {
    let args = vec!["clarg", "-b", "file\tname.txt"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.block_access_to, vec!["file\tname.txt"]);
}

// Note: newlines in command line args are unusual and may be handled differently
// by different shells, so we test tab which is more reliably passed through
