use eyre::{Result, WrapErr};
use regex::Regex;

use crate::util::truncate;

pub struct BlockedCommandsRule {
    patterns: Vec<(Regex, String)>, // (compiled regex, original pattern string)
}

impl BlockedCommandsRule {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let compiled: Result<Vec<_>> = patterns
            .iter()
            .map(|p| {
                log::debug!("blocked_commands: compiling regex '{}'", p);
                Regex::new(p)
                    .map(|r| (r, p.clone()))
                    .wrap_err_with(|| format!("invalid command regex: {p}"))
            })
            .collect();
        Ok(Self {
            patterns: compiled?,
        })
    }

    /// Check if a command is blocked. Returns Some(reason) if blocked, None if allowed.
    pub fn check(&self, command: &str) -> Option<String> {
        log::debug!(
            "blocked_commands: checking command against {} patterns",
            self.patterns.len()
        );
        for (regex, original) in &self.patterns {
            if regex.is_match(command) {
                log::info!("blocked_commands: matched pattern '{}'", original);
                return Some(format!(
                    "Blocked by `clarg`: command '{}' is forbidden because it matched the pattern '{}'",
                    truncate(command, 100),
                    original
                ));
            }
        }
        log::debug!("blocked_commands: no patterns matched");
        None
    }
}
