use clarg::config::Config;
use std::path::PathBuf;
use super::helpers::create_yaml_file;

// ============================================================================
// Config::from_yaml TESTS - Many Patterns/Commands
// ============================================================================

#[test]
fn test_from_yaml_many_patterns() {
    let mut patterns = vec![];
    for i in 0..50 {
        patterns.push(format!("  - \"pattern{}.txt\"", i));
    }
    let yaml = format!("block_access_to:\n{}", patterns.join("\n"));
    let file = create_yaml_file(&yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 50);
    assert_eq!(config.block_access_to[0], "pattern0.txt");
    assert_eq!(config.block_access_to[25], "pattern25.txt");
    assert_eq!(config.block_access_to[49], "pattern49.txt");
}

#[test]
fn test_from_yaml_many_commands() {
    let mut commands = vec![];
    for i in 0..50 {
        commands.push(format!("  - \"command{}\"", i));
    }
    let yaml = format!("commands_forbidden:\n{}", commands.join("\n"));
    let file = create_yaml_file(&yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 50);
    assert_eq!(config.commands_forbidden[0], "command0");
    assert_eq!(config.commands_forbidden[25], "command25");
    assert_eq!(config.commands_forbidden[49], "command49");
}

#[test]
fn test_from_yaml_very_large_arrays() {
    let mut patterns = vec![];
    for i in 0..100 {
        patterns.push(format!("  - \"pattern{}.txt\"", i));
    }
    let mut commands = vec![];
    for i in 0..75 {
        commands.push(format!("  - \"command{}\"", i));
    }
    let yaml = format!(
        "block_access_to:\n{}\ncommands_forbidden:\n{}",
        patterns.join("\n"),
        commands.join("\n")
    );
    let file = create_yaml_file(&yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 100);
    assert_eq!(config.commands_forbidden.len(), 75);
}

// ============================================================================
// Config::from_yaml TESTS - Unicode Patterns
// ============================================================================

#[test]
fn test_from_yaml_unicode_patterns() {
    let yaml = r#"
block_access_to:
  - "файл.txt"
  - "文件.md"
  - "ファイル.rs"
  - "파일.yaml"
  - "emoji_🔥.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 5);
    assert_eq!(config.block_access_to[0], "файл.txt");
    assert_eq!(config.block_access_to[1], "文件.md");
    assert_eq!(config.block_access_to[2], "ファイル.rs");
    assert_eq!(config.block_access_to[3], "파일.yaml");
    assert_eq!(config.block_access_to[4], "emoji_🔥.log");
}

#[test]
fn test_from_yaml_unicode_commands() {
    let yaml = r#"
commands_forbidden:
  - "приказ"
  - "命令"
  - "コマンド"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 3);
    assert_eq!(config.commands_forbidden[0], "приказ");
    assert_eq!(config.commands_forbidden[1], "命令");
    assert_eq!(config.commands_forbidden[2], "コマンド");
}

#[test]
fn test_from_yaml_unicode_log_path() {
    let yaml = r#"
log_to: "/tmp/логи/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("/tmp/логи/clarg.log")));
}

// ============================================================================
// Config::from_yaml TESTS - Regex Patterns
// ============================================================================

#[test]
fn test_from_yaml_regex_patterns_in_commands_forbidden() {
    let yaml = r#"
commands_forbidden:
  - ".*"
  - "^rm"
  - "sudo$"
  - "\\s+dd\\s+"
  - "[a-z]+"
  - "\\d{3}"
  - "(delete|remove)"
  - ".*--force.*"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 8);
    assert_eq!(config.commands_forbidden[0], ".*");
    assert_eq!(config.commands_forbidden[1], "^rm");
    assert_eq!(config.commands_forbidden[2], "sudo$");
    assert_eq!(config.commands_forbidden[3], "\\s+dd\\s+");
    assert_eq!(config.commands_forbidden[4], "[a-z]+");
    assert_eq!(config.commands_forbidden[5], "\\d{3}");
    assert_eq!(config.commands_forbidden[6], "(delete|remove)");
    assert_eq!(config.commands_forbidden[7], ".*--force.*");
}

#[test]
fn test_from_yaml_complex_regex_patterns() {
    let yaml = r#"
commands_forbidden:
  - "(?i)password"
  - "\\b(secret|key|token)\\b"
  - "^(curl|wget).*\\|.*sh$"
  - "chmod\\s+[0-7]{3,4}"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.commands_forbidden.len(), 4);
    assert_eq!(config.commands_forbidden[0], "(?i)password");
    assert_eq!(config.commands_forbidden[1], "\\b(secret|key|token)\\b");
    assert_eq!(config.commands_forbidden[2], "^(curl|wget).*\\|.*sh$");
    assert_eq!(config.commands_forbidden[3], "chmod\\s+[0-7]{3,4}");
}

// ============================================================================
// Config::from_yaml TESTS - Gitignore Patterns
// ============================================================================

#[test]
fn test_from_yaml_gitignore_glob_patterns() {
    let yaml = r#"
block_access_to:
  - "*.log"
  - "**/*.tmp"
  - "file?.txt"
  - "[abc].md"
  - "{a,b,c}.yaml"
  - "**"
  - "dir/**/*"
  - "!important.txt"
  - "*.{js,ts}"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 9);
    assert_eq!(config.block_access_to[0], "*.log");
    assert_eq!(config.block_access_to[1], "**/*.tmp");
    assert_eq!(config.block_access_to[2], "file?.txt");
    assert_eq!(config.block_access_to[3], "[abc].md");
    assert_eq!(config.block_access_to[4], "{a,b,c}.yaml");
    assert_eq!(config.block_access_to[5], "**");
    assert_eq!(config.block_access_to[6], "dir/**/*");
    assert_eq!(config.block_access_to[7], "!important.txt");
    assert_eq!(config.block_access_to[8], "*.{js,ts}");
}

#[test]
fn test_from_yaml_complex_gitignore_patterns() {
    let yaml = r#"
block_access_to:
  - "/**/node_modules"
  - "**/target/**"
  - "*.pyc"
  - "__pycache__/"
  - ".DS_Store"
  - "Thumbs.db"
  - "*.swp"
  - "*~"
  - "/.idea"
  - "/.vscode"
  - "/build/"
  - "/dist/"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 12);
    assert_eq!(config.block_access_to[0], "/**/node_modules");
    assert_eq!(config.block_access_to[1], "**/target/**");
    assert_eq!(config.block_access_to[2], "*.pyc");
    assert_eq!(config.block_access_to[11], "/dist/");
}

#[test]
fn test_from_yaml_gitignore_negation_patterns() {
    let yaml = r#"
block_access_to:
  - "*.log"
  - "!important.log"
  - "*.tmp"
  - "!keep.tmp"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.block_access_to.len(), 4);
    assert_eq!(config.block_access_to[0], "*.log");
    assert_eq!(config.block_access_to[1], "!important.log");
    assert_eq!(config.block_access_to[2], "*.tmp");
    assert_eq!(config.block_access_to[3], "!keep.tmp");
}

// ============================================================================
// Config::from_yaml TESTS - Path Types
// ============================================================================

#[test]
fn test_from_yaml_log_to_relative_path() {
    let yaml = r#"
log_to: "logs/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("logs/clarg.log")));
}

#[test]
fn test_from_yaml_log_to_absolute_path() {
    let yaml = r#"
log_to: "/var/log/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("/var/log/clarg.log")));
}

#[test]
fn test_from_yaml_log_to_home_directory() {
    let yaml = r#"
log_to: "~/logs/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("~/logs/clarg.log")));
}

#[test]
fn test_from_yaml_log_to_current_directory() {
    let yaml = r#"
log_to: "./clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("./clarg.log")));
}

#[test]
fn test_from_yaml_log_to_parent_directory() {
    let yaml = r#"
log_to: "../logs/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(config.log_to, Some(PathBuf::from("../logs/clarg.log")));
}

#[test]
fn test_from_yaml_log_to_with_spaces() {
    let yaml = r#"
log_to: "/path with spaces/clarg.log"
"#;
    let file = create_yaml_file(yaml);
    let config = Config::from_yaml(&file.path().to_path_buf()).unwrap();

    assert_eq!(
        config.log_to,
        Some(PathBuf::from("/path with spaces/clarg.log"))
    );
}

// ============================================================================
