use eyre::{Result, WrapErr};
use regex::Regex;

pub struct BlockedCommandsRule {
    patterns: Vec<(Regex, String)>, // (compiled regex, original pattern string)
}

impl BlockedCommandsRule {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let compiled: Result<Vec<_>> = patterns
            .iter()
            .map(|p| {
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
        for (regex, original) in &self.patterns {
            if regex.is_match(command) {
                return Some(format!(
                    "Blocked by `clarg`: command '{}' is forbidden because it matched the pattern '{}'",
                    truncate(command, 100),
                    original
                ));
            }
        }
        None
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..s.floor_char_boundary(max)]
    }
}
