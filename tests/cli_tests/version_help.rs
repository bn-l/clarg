use clap::Parser;
use clarg::cli::Cli;

// ============================================================================
// VERSION AND HELP TESTS
// ============================================================================

#[test]
fn test_version_flag_short() {
    let args = vec!["clarg", "-V"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn test_version_flag_long() {
    let args = vec!["clarg", "--version"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn test_help_flag_short() {
    let args = vec!["clarg", "-h"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn test_help_flag_long() {
    let args = vec!["clarg", "--help"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn test_version_with_other_flags_shows_version() {
    // Version flag takes precedence
    let args = vec!["clarg", "-V", "-b", ".env"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn test_help_with_other_flags_shows_help() {
    // Help flag takes precedence
    let args = vec!["clarg", "-h", "-b", ".env"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn test_version_at_end() {
    let args = vec!["clarg", "-b", ".env", "-V"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn test_help_at_end() {
    let args = vec!["clarg", "-b", ".env", "-h"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn test_version_and_help_version_wins() {
    // When both are provided, first one wins
    let args = vec!["clarg", "-V", "-h"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn test_help_and_version_help_wins() {
    // When both are provided, first one wins
    let args = vec!["clarg", "-h", "-V"];
    let result = Cli::try_parse_from(args);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}
