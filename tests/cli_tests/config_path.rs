use clap::Parser;
use clarg::cli::Cli;

#[test]
fn test_config_path_positional_simple() {
    let args = vec!["clarg", "config.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("config.yaml".into()));
    assert!(cli.block_access_to.is_empty());
    assert!(cli.commands_forbidden.is_empty());
    assert!(cli.log_to.is_none());
    assert!(!cli.internal_access_only);
}

#[test]
fn test_config_path_positional_absolute() {
    let args = vec!["clarg", "/etc/clarg/config.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("/etc/clarg/config.yaml".into()));
}

#[test]
fn test_config_path_positional_relative() {
    let args = vec!["clarg", "./config/settings.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("./config/settings.yaml".into()));
}

#[test]
fn test_config_path_with_spaces() {
    let args = vec!["clarg", "My Config/settings.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("My Config/settings.yaml".into()));
}

#[test]
fn test_config_path_very_long() {
    let long_path = "/very/long/path/to/configuration/files/in/a/deep/directory/structure/with/many/segments/config.yaml";
    let args = vec!["clarg", long_path];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some(long_path.into()));
}

#[test]
fn test_config_path_with_tilde() {
    let args = vec!["clarg", "~/.config/clarg/config.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("~/.config/clarg/config.yaml".into()));
}

#[test]
fn test_config_path_with_extension_yaml() {
    let args = vec!["clarg", "config.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("config.yaml".into()));
}

#[test]
fn test_config_path_with_extension_yml() {
    let args = vec!["clarg", "config.yml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("config.yml".into()));
}

#[test]
fn test_config_path_with_extension_json() {
    let args = vec!["clarg", "config.json"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("config.json".into()));
}

#[test]
fn test_config_path_no_extension() {
    let args = vec!["clarg", "config"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("config".into()));
}

#[test]
fn test_config_path_multiple_dots() {
    let args = vec!["clarg", "my.config.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("my.config.yaml".into()));
}

#[test]
fn test_config_path_unicode() {
    let args = vec!["clarg", "配置/настройка/config™.yaml"];
    let cli = Cli::try_parse_from(args).unwrap();

    assert_eq!(cli.config_path, Some("配置/настройка/config™.yaml".into()));
}
