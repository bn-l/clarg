use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use eyre::{Result, WrapErr, bail};

use clarg::cli::Cli;
use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::logging;
use clarg::output::{output_deny, print_friendly_usage};
use clarg::router::{RuleSet, Verdict};

fn project_root(hook_input: &HookInput) -> PathBuf {
    std::env::var_os("CLAUDE_PROJECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| hook_input.cwd.clone())
}

fn run(cli: Cli) -> Result<Verdict> {
    let config = Config::from_cli(cli)?;

    log::info!(
        "rules: {} blocked file patterns, {} blocked command patterns, internal_only={}, no_root={}, no_system_dirs={}, no_unknown_tools={}",
        config.block_access_to.len(),
        config.commands_forbidden.len(),
        config.internal_access_only,
        config.no_root,
        config.no_system_dirs,
        config.no_unknown_tools,
    );

    // Read stdin
    let mut input_str = String::new();
    std::io::stdin()
        .read_to_string(&mut input_str)
        .wrap_err("failed to read stdin")?;

    if input_str.trim().is_empty() {
        bail!("empty stdin — expected JSON hook input");
    }

    log::debug!("received {} bytes of hook input", input_str.len());

    // Parse JSON — fail closed on parse error
    let hook_input: HookInput = serde_json::from_str(&input_str)
        .wrap_err("failed to parse hook input JSON")?;

    log::info!(
        "hook: tool={} cwd={}",
        hook_input.tool_name,
        hook_input.cwd.display(),
    );

    let root = project_root(&hook_input);
    log::debug!("project root: {}", root.display());

    // Build rule set
    let ruleset = RuleSet::build(&config, &root)
        .wrap_err("failed to build rule set")?;

    // Evaluate
    let verdict = ruleset.evaluate(&hook_input);

    match &verdict {
        Verdict::Allow => {
            log::info!("verdict: tool={} ALLOW", hook_input.tool_name);
        }
        Verdict::Deny(reason) => {
            log::warn!("verdict: tool={} DENY reason={}", hook_input.tool_name, reason);
        }
    }

    Ok(verdict)
}

fn main() -> ExitCode {
    color_eyre::install().ok();

    // Parse CLI args first so --help/-V work even from a TTY
    let cli = Cli::parse();

    // TTY check — if user ran clarg interactively with no meaningful args, show friendly usage
    if std::io::stdin().is_terminal() {
        print_friendly_usage();
        return ExitCode::SUCCESS;
    }

    // Initialize logging (must happen before run() so config loading is logged)
    let _logger = logging::init(cli.log_dir.as_deref());

    match run(cli) {
        Ok(Verdict::Allow) => ExitCode::SUCCESS,
        Ok(Verdict::Deny(reason)) => {
            output_deny(&reason);
            ExitCode::from(2)
        }
        Err(e) => {
            log::error!("internal error: {e:#}");
            // Fail closed: any internal error blocks the operation
            let reason = format!(
                "Blocked by `clarg`: internal error — {e:#}. \
                 Failing closed for safety. Fix the clarg configuration to resolve this."
            );
            output_deny(&reason);
            ExitCode::from(2)
        }
    }
}
