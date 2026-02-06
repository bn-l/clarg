use clap::Parser;
use clarg::cli::Cli;

#[test]
fn test_default_args_no_flags() {
    let args = vec!["clarg"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert!(cli.config_path.is_none());
    assert!(cli.block_access_to.is_empty());
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.log_to.is_none());
    assert!(!cli.internal_access_only);
}

#[test]
fn test_default_args_every_field_is_default() {
    let args = vec!["clarg"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, None, "config_path should be None");
    assert_eq!(cli.block_access_to, Vec::<String>::new(), "block_access_to should be empty");
    assert_eq!(cli.commands_forbidden, Vec::<String>::new(), "commands_forbidden should be empty");
    assert_eq!(cli.log_to, None, "log_to should be None");
    assert_eq!(cli.internal_access_only, false, "internal_access_only should be false");
}
