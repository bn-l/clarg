use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use clap::Parser;
use eyre::{Result, WrapErr, bail};

use clarg::cli::Cli;
use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::output::{format_log_entry, log_message, output_deny, print_friendly_usage};
use clarg::router::{RuleSet, Verdict};

fn project_root(hook_input: &HookInput) -> PathBuf {
    std::env::var_os("CLAUDE_PROJECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| hook_input.cwd.clone())
}

fn run(cli: Cli) -> Result<Verdict> {
    let config = Config::from_cli(cli)?;
    let log_path = config.log_to.clone();

    // Read stdin
    let mut input_str = String::new();
    std::io::stdin()
        .read_to_string(&mut input_str)
        .wrap_err("failed to read stdin")?;

    if input_str.trim().is_empty() {
        bail!("empty stdin — expected JSON hook input");
    }

    // Parse JSON — fail closed on parse error
    let hook_input: HookInput = serde_json::from_str(&input_str)
        .wrap_err("failed to parse hook input JSON")?;

    let root = project_root(&hook_input);

    // Build rule set
    let ruleset = RuleSet::build(&config, &root)
        .wrap_err("failed to build rule set")?;

    // Evaluate
    let verdict = ruleset.evaluate(&hook_input);

    // Log
    match &verdict {
        Verdict::Allow => {
            let entry = format_log_entry(&hook_input.tool_name, "allow", "");
            log_message(log_path.as_deref(), &entry);
        }
        Verdict::Deny(reason) => {
            let entry =
                format_log_entry(&hook_input.tool_name, "deny", reason);
            log_message(log_path.as_deref(), &entry);
        }
    }

    Ok(verdict)
}

fn main() {
    color_eyre::install().ok();

    // Parse CLI args first so --help/-V work even from a TTY
    let cli = Cli::parse();

    // TTY check — if user ran clarg interactively with no meaningful args, show friendly usage
    if std::io::stdin().is_terminal() {
        print_friendly_usage();
        std::process::exit(0);
    }

    match run(cli) {
        Ok(Verdict::Allow) => std::process::exit(0),
        Ok(Verdict::Deny(reason)) => {
            output_deny(&reason);
            std::process::exit(2);
        }
        Err(e) => {
            // Fail closed: any internal error blocks the operation
            let reason = format!(
                "Blocked by `clarg`: internal error — {e:#}. \
                 Failing closed for safety. Fix the clarg configuration to resolve this."
            );
            output_deny(&reason);
            std::process::exit(2);
        }
    }
}
