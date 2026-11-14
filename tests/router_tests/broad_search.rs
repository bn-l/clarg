//! `no_broad_search`: nothing may search, list or glob-enumerate the home
//! folder or anything above it; subfolders stay allowed. With
//! `internal_access_only`, no search may leave the project.

use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use tempfile::TempDir;

const DENY: bool = true;
const ALLOW: bool = false;

fn config(no_broad_search: bool, internal_only: bool) -> Config {
    Config {
        no_broad_search,
        internal_access_only: internal_only,
        ..Config::default()
    }
}

fn input(tool: &str, tool_input: serde_json::Value, cwd: &std::path::Path) -> HookInput {
    serde_json::from_value(json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    }))
    .unwrap()
}

/// Evaluate each `(tool, tool_input, expect_deny)` and report every mismatch.
fn check(cfg: &Config, cases: &[(&str, serde_json::Value, bool)]) {
    if std::env::var_os("HOME").is_none_or(|h| h.is_empty()) {
        return; // the rule needs $HOME
    }
    let tmp = TempDir::new().unwrap();
    let ruleset = RuleSet::build(cfg, tmp.path()).unwrap();
    let mut failures = Vec::new();
    for (tool, tool_input, expect_deny) in cases {
        let verdict = ruleset.evaluate(&input(tool, tool_input.clone(), tmp.path()));
        if matches!(verdict, Verdict::Deny(_)) != *expect_deny {
            failures.push(format!("{tool} {tool_input}: expected {}, got {verdict:?}", if *expect_deny { "deny" } else { "allow" }));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

fn bash(cmd: &str, deny: bool) -> (&'static str, serde_json::Value, bool) {
    ("Bash", json!({ "command": cmd }), deny)
}

#[test]
fn test_searching_home_or_above_is_denied() {
    check(&config(true, false), &[
        bash("fd -t f 'mako.rb' ~", DENY),
        bash("rg foo ~", DENY),
        bash("rg foo $HOME", DENY),
        bash("find ~ -name x", DENY),
        bash("find / -name x", DENY),
        bash("fd x /Users", DENY),
        bash("grep -r foo ~/", DENY),
        bash("ag foo ~", DENY),
        bash("ack foo ~", DENY),
        bash("fd --search-path ~ x", DENY),
        bash("fd --base-directory ~ x", DENY),
        bash("cd ~ && rg x", DENY),
    ]);
}

#[test]
fn test_listing_home_or_above_is_denied() {
    check(&config(true, false), &[
        bash("ls ~", DENY),
        bash("ls -la ~", DENY),
        bash("ls -R ~", DENY),
        bash("tree ~", DENY),
        bash("du -sh ~", DENY),
        bash("eza ~", DENY),
        bash("lsd ~", DENY),
        bash("cd ~ && ls", DENY),
        bash("ls /", DENY),
    ]);
}

#[test]
fn test_globs_enumerating_home_or_above_are_denied() {
    check(&config(true, false), &[
        bash("ls ~/*", DENY),
        bash("echo ~/*", DENY),
        bash("du -sh ~/*", DENY),
        bash("cat ~/.c*", DENY),
        bash("ls /Users/*/Desktop", DENY),
        // Quoted: a literal name, not a listing.
        bash("cat '~/*'", ALLOW),
        bash("ls ~/.config/*", ALLOW),
        bash("rm -rf build/*", ALLOW),
    ]);
}

#[test]
fn test_subfolders_and_known_paths_are_allowed() {
    check(&config(true, false), &[
        bash("cat ~/.zshrc", ALLOW),
        bash("grep foo ~/.zshrc", ALLOW),
        bash("ls ~/.config", ALLOW),
        bash("rg x ~/projects", ALLOW),
        bash("fd x ~/projects", ALLOW),
        bash("cd ~/x && ls", ALLOW),
        bash("echo $HOME", ALLOW),
        bash("ls -d ~", ALLOW),
        bash("fd x", ALLOW),
        bash("rg foo src/", ALLOW),
        bash("ls", ALLOW),
        bash("find /tmp/x -name y", ALLOW),
    ]);
}

#[test]
fn test_inline_code_listing_home_is_denied() {
    let home = std::env::var("HOME").unwrap_or_default();
    check(&config(true, false), &[
        bash(&format!("python3 -c 'import os; print(os.listdir(\"{home}\"))'"), DENY),
        bash(&format!("python3 -c 'print(open(\"{home}/.zshrc\").read())'"), ALLOW),
    ]);
}

#[test]
fn test_grep_and_glob_tools() {
    check(&config(true, false), &[
        ("Grep", json!({ "pattern": "foo", "path": "~" }), DENY),
        ("Glob", json!({ "pattern": "*", "path": "~" }), DENY),
        ("Glob", json!({ "pattern": "~/**/x" }), DENY),
        ("Grep", json!({ "pattern": "foo" }), ALLOW),
        ("Grep", json!({ "pattern": "foo", "path": "src" }), ALLOW),
        ("Glob", json!({ "pattern": "**/*.rs" }), ALLOW),
        ("Glob", json!({ "pattern": ".config/**/*.toml", "path": "~" }), ALLOW),
    ]);
}

#[test]
fn test_flag_off_allows_everything_here() {
    check(&config(false, false), &[
        bash("fd -t f 'mako.rb' ~", ALLOW),
        bash("ls ~", ALLOW),
        bash("echo ~/*", ALLOW),
        ("Glob", json!({ "pattern": "~/**/x" }), ALLOW),
    ]);
}

#[test]
fn test_internal_only_searches_stay_in_the_project() {
    check(&config(false, true), &[
        bash("fd --search-path ~ x", DENY),
        bash("rg foo ~/projects", DENY),
        bash("find /tmp -name x", DENY),
        ("Glob", json!({ "pattern": "~/**/x" }), DENY),
        ("Glob", json!({ "pattern": "/tmp/**/x" }), DENY),
        bash("rg foo src/", ALLOW),
        bash("fd x", ALLOW),
        ("Glob", json!({ "pattern": "**/*.rs" }), ALLOW),
        ("Grep", json!({ "pattern": "foo" }), ALLOW),
    ]);
}

#[test]
fn test_fd_pattern_is_not_a_path() {
    // Previously `mako.rb` was checked as a file and matched `-b mako.rb`.
    let cfg = Config { block_access_to: vec!["mako.rb".to_string()], ..Config::default() };
    check(&cfg, &[bash("fd mako.rb src", ALLOW), bash("cat mako.rb", DENY)]);
}
