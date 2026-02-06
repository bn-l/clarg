use clarg::cli::Cli;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

pub fn create_yaml_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

pub fn create_cli_no_flags() -> Cli {
    Cli {
        config_path: None,
        block_access_to: vec![],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    }
}

pub fn create_cli_all_flags() -> Cli {
    Cli {
        config_path: None,
        block_access_to: vec![".env".to_string(), "*.secret".to_string()],
        commands_forbidden: vec!["rm -rf".to_string(), "sudo".to_string()],
        log_to: Some(PathBuf::from("/tmp/clarg.log")),
        internal_access_only: true,
    }
}

pub fn create_cli_partial_flags() -> Cli {
    Cli {
        config_path: None,
        block_access_to: vec![".env".to_string()],
        commands_forbidden: vec![],
        log_to: None,
        internal_access_only: false,
    }
}
