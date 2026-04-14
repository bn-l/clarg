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
    #[arg(conflicts_with_all = [
        "block_access_to",
        "commands_forbidden",
        "log_dir",
        "internal_access_only",
        "no_root",
        "no_system_dirs",
        "no_unknown_tools",
    ])]
    pub config_path: Option<PathBuf>,

    /// Gitignore-style file patterns to block (comma or space separated).
    /// Patterns starting with `~`, `~/`, `$HOME`, or `$HOME/` are
    /// home-expanded and match absolute paths anywhere on the filesystem
    /// (e.g. `~/.ssh/**`). Other patterns use classic gitignore semantics
    /// anchored at the project root for in-project paths, and additionally
    /// match against the absolute form for paths *outside* the project —
    /// so `/etc/shadow` blocks the real `/etc/shadow`, and unanchored
    /// patterns like `.env` block any matching basename anywhere clarg
    /// sees a tool target. Use `-i` for blanket "everything outside the
    /// project" blocking.
    #[arg(short = 'b', long = "block-access-to", value_delimiter = ',', num_args = 1..)]
    pub block_access_to: Vec<String>,

    /// Regex patterns for commands to forbid (comma or space separated)
    #[arg(short = 'c', long = "commands-forbidden", value_delimiter = ',', num_args = 1..)]
    pub commands_forbidden: Vec<String>,

    /// Directory to write logs to (default: $XDG_STATE_HOME/clarg or ~/.local/state/clarg)
    #[arg(short = 'l', long = "log-dir")]
    pub log_dir: Option<PathBuf>,

    /// Block ALL filesystem access outside the project directory
    #[arg(short = 'i', long = "internal-access-only")]
    pub internal_access_only: bool,

    /// Block commands/tools targeting the filesystem root '/'
    /// (including glob forms like /*, /**, /./*, /../*).
    #[arg(long = "no-root")]
    pub no_root: bool,

    /// Block commands/tools targeting OS-level system directories
    /// (e.g. /etc, /usr, /var, /System, /Library). Paths inside the
    /// project root are exempt via an escape hatch.
    #[arg(long = "no-system-dirs")]
    pub no_system_dirs: bool,

    /// Deny any tool clarg does not explicitly recognize (includes
    /// MCP tools like `mcp__filesystem__read_file`).
    #[arg(long = "no-unknown-tools")]
    pub no_unknown_tools: bool,
}
