use eyre::{Result, WrapErr};
use serde::Deserialize;
use std::path::PathBuf;

use crate::cli::Cli;

/// Unified configuration, built from either CLI args or a YAML file.
#[derive(Debug, Default)]
pub struct Config {
    pub block_access_to: Vec<String>,
    pub commands_forbidden: Vec<String>,
    pub log_dir: Option<PathBuf>,
    pub internal_access_only: bool,
    pub no_root: bool,
    pub no_system_dirs: bool,
    pub no_unknown_tools: bool,
}

/// Nested `special_flags` section of the YAML config. `deny_unknown_fields`
/// is scoped here so typos inside `special_flags` fail fast, while
/// top-level unknown keys remain silently ignored (existing behavior).
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct SpecialFlagsYaml {
    #[serde(default)]
    no_root: bool,
    #[serde(default)]
    no_system_dirs: bool,
    #[serde(default)]
    no_unknown_tools: bool,
}

/// Intermediate struct for YAML deserialization.
#[derive(Deserialize, Debug)]
struct YamlConfig {
    #[serde(default)]
    block_access_to: Vec<String>,
    #[serde(default)]
    commands_forbidden: Vec<String>,
    #[serde(default)]
    log_dir: Option<PathBuf>,
    #[serde(default)]
    internal_access_only: bool,
    #[serde(default)]
    special_flags: SpecialFlagsYaml,
}

impl Config {
    pub fn from_cli(cli: Cli) -> Result<Self> {
        if let Some(config_path) = cli.config_path {
            // If the config path is relative, resolve it against CLAUDE_PROJECT_DIR
            // so that `cd` during a session doesn't break config loading.
            let config_path = if config_path.is_relative() {
                if let Some(project_dir) = std::env::var_os("CLAUDE_PROJECT_DIR") {
                    let resolved = PathBuf::from(project_dir).join(&config_path);
                    log::debug!(
                        "resolved relative config path against CLAUDE_PROJECT_DIR: {}",
                        resolved.display()
                    );
                    resolved
                } else {
                    config_path
                }
            } else {
                config_path
            };
            let config = Self::from_yaml(&config_path)?;
            log::info!("config loaded from YAML: {}", config_path.display());
            Ok(config)
        } else {
            log::info!("config loaded from CLI flags");
            Ok(Self {
                block_access_to: cli.block_access_to,
                commands_forbidden: cli.commands_forbidden,
                log_dir: cli.log_dir,
                internal_access_only: cli.internal_access_only,
                no_root: cli.no_root,
                no_system_dirs: cli.no_system_dirs,
                no_unknown_tools: cli.no_unknown_tools,
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
            log_dir: yaml.log_dir,
            internal_access_only: yaml.internal_access_only,
            no_root: yaml.special_flags.no_root,
            no_system_dirs: yaml.special_flags.no_system_dirs,
            no_unknown_tools: yaml.special_flags.no_unknown_tools,
        })
    }
}
