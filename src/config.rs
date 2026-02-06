use eyre::{Result, WrapErr};
use serde::Deserialize;
use std::path::PathBuf;

use crate::cli::Cli;

/// Unified configuration, built from either CLI args or a YAML file.
#[derive(Debug, Default)]
pub struct Config {
    pub block_access_to: Vec<String>,
    pub commands_forbidden: Vec<String>,
    pub log_to: Option<PathBuf>,
    pub internal_access_only: bool,
}

/// Intermediate struct for YAML deserialization.
#[derive(Deserialize, Debug)]
struct YamlConfig {
    #[serde(default)]
    block_access_to: Vec<String>,
    #[serde(default)]
    commands_forbidden: Vec<String>,
    #[serde(default)]
    log_to: Option<PathBuf>,
    #[serde(default)]
    internal_access_only: bool,
}

impl Config {
    pub fn from_cli(cli: Cli) -> Result<Self> {
        if let Some(config_path) = cli.config_path {
            Self::from_yaml(&config_path)
        } else {
            Ok(Self {
                block_access_to: cli.block_access_to,
                commands_forbidden: cli.commands_forbidden,
                log_to: cli.log_to,
                internal_access_only: cli.internal_access_only,
            })
        }
    }

    pub fn from_yaml(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("failed to read config file: {}", path.display()))?;
        let yaml: YamlConfig = serde_yaml::from_str(&contents)
            .wrap_err_with(|| format!("failed to parse YAML config: {}", path.display()))?;
        Ok(Self {
            block_access_to: yaml.block_access_to,
            commands_forbidden: yaml.commands_forbidden,
            log_to: yaml.log_to,
            internal_access_only: yaml.internal_access_only,
        })
    }
}
