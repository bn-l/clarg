use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "clarg",
    version,
    about = "Claude Code hook handler for blocking commands and file access",
    long_about = "A PreToolUse hook for Claude Code that blocks access to files, \
                  commands, and paths outside the project boundary.\n\n\
                  USAGE AS A HOOK:\n  \
                  Add to .claude/settings.json under hooks.PreToolUse\n\n\
                  EXAMPLES:\n  \
                  clarg -b '.env,*.secret' -c 'rm -rf' -i\n  \
                  clarg config.yaml"
)]
pub struct Cli {
    /// YAML config path — mutually exclusive with all flags
    #[arg(conflicts_with_all = ["block_access_to", "commands_forbidden", "log_to", "internal_access_only"])]
    pub config_path: Option<PathBuf>,

    /// Gitignore-style file patterns to block (comma or space separated)
    #[arg(short = 'b', long = "block-access-to", value_delimiter = ',', num_args = 1..)]
    pub block_access_to: Vec<String>,

    /// Regex patterns for commands to forbid (comma or space separated)
    #[arg(short = 'c', long = "commands-forbidden", value_delimiter = ',', num_args = 1..)]
    pub commands_forbidden: Vec<String>,

    /// Path of file to log to (default: stderr)
    #[arg(short = 'l', long = "log-to")]
    pub log_to: Option<PathBuf>,

    /// Block ALL filesystem access outside the project directory
    #[arg(short = 'i', long = "internal-access-only")]
    pub internal_access_only: bool,
}
