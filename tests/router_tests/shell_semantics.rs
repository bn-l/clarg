//! Shell-semantics regression tables: command boundaries, command
//! substitution, working-directory and variable tracking, quoted globs,
//! inline-code precision, operands that are never paths, and tools that
//! run shell commands. Each case names the verdict it must produce.

use clarg::config::Config;
use clarg::hook_input::HookInput;
use clarg::router::{RuleSet, Verdict};
use serde_json::json;
use std::path::Path;
use tempfile::TempDir;

fn config(internal_only: bool, blocked: &[&str]) -> Config {
    Config {
        block_access_to: blocked.iter().map(|s| s.to_string()).collect(),
        commands_forbidden: vec![],
        log_dir: None,
        internal_access_only: internal_only,
        no_root: !internal_only,
        no_system_dirs: !internal_only,
        no_unknown_tools: false,
        no_broad_search: false,
    }
}

fn input(tool: &str, tool_input: serde_json::Value, cwd: &Path) -> HookInput {
    serde_json::from_value(json!({
        "session_id": "test-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    }))
    .unwrap()
}

/// Evaluate each `(command, expect_deny)` and report every mismatch.
fn check_bash(cfg: &Config, cases: &[(&str, bool)]) {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir(tmp.path().join("sub")).unwrap();
    let ruleset = RuleSet::build(cfg, tmp.path()).unwrap();
    let mut failures = Vec::new();
    for (cmd, expect_deny) in cases {
        let verdict = ruleset.evaluate(&input("Bash", json!({ "command": cmd }), tmp.path()));
        let denied = matches!(verdict, Verdict::Deny(_));
        if denied != *expect_deny {
            failures.push(format!("{cmd:?}: expected {}, got {verdict:?}", if *expect_deny { "deny" } else { "allow" }));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

const DENY: bool = true;
const ALLOW: bool = false;

// ============================================================================
// S1: newlines, background `&`, comments
// ============================================================================

#[test]
fn test_newlines_and_background_separate_commands() {
    check_bash(&config(false, &[]), &[
        ("cd src\nrm -rf /", DENY),
        ("bash build.sh\nrm -rf /*", DENY),
        ("python3 x.py\ncat /etc/passwd", DENY),
        ("node x.js\nls /", DENY),
        ("python3 x.py & cat /etc/passwd", DENY),
        ("ls 2>&1 > /etc/x", DENY),
        ("ls &> /etc/x", DENY),
        ("echo a & wait", ALLOW),
        ("cat a \\\n  b", ALLOW),
    ]);
    check_bash(&config(true, &[]), &[("cd src\ncat /etc/passwd", DENY)]);
}

#[test]
fn test_comments_are_inert() {
    check_bash(&config(false, &[]), &[
        ("# usage: cat <<EOF\nrm -rf /", DENY),
        ("# don't\ncat /{etc,var}/passwd", DENY),
        ("# don't\nrm -rf /*", DENY),
        ("cat a # then > /etc/x", ALLOW),
        ("# header: /* section */\ncat a.css", ALLOW),
        ("echo foo # comment with 'quote", ALLOW),
    ]);
}

// ============================================================================
// S2: command substitution
// ============================================================================

#[test]
fn test_command_substitution_bodies_are_checked() {
    check_bash(&config(false, &[]), &[
        ("echo \"$(rm -rf /*)\"", DENY),
        ("x=$(cat /etc/passwd)", DENY),
        ("x=`cat /etc/passwd`", DENY),
        ("diff <(cat /etc/passwd) a.txt", DENY),
        ("cat $(echo /etc/passwd)", DENY),
        ("cat > notes.txt <<EOF\n$(rm -rf /)\nEOF", DENY),
        // Quoted heredoc delimiter: the body is literal.
        ("cat > notes.txt <<'EOF'\n$(rm -rf /)\nEOF", ALLOW),
        // Single quotes: not a substitution.
        ("echo '$(rm -rf /)'", ALLOW),
        ("x=$(( 1 + 2 )); echo $x", ALLOW),
        ("echo $(pwd)/foo", ALLOW),
    ]);
}

// ============================================================================
// S3: working directory
// ============================================================================

#[test]
fn test_cd_is_followed_within_a_command() {
    check_bash(&config(false, &[]), &[
        ("cd .. && cd .. && cd .. && cd .. && cd .. && cd .. && cd .. && cd .. && cd .. && cd .. && rm -rf *", DENY),
        ("cd /Users && rm -rf ../*", DENY),
        ("cd /tmp && rm -rf ../etc", DENY),
        ("cd -P / && rm -rf *", DENY),
        ("cd -L /etc && cat passwd", DENY),
        ("pushd /tmp && popd && cd /tmp && cat ../etc/hosts", DENY),
        // After reserved words and inside groups.
        ("if true; then cd /tmp; fi; rm -rf ../etc", DENY),
        ("(cd /tmp && rm -rf ../etc)", DENY),
        ("{ cd /tmp; rm -rf ../etc; }", DENY),
        ("for d in a; do cd /tmp && rm -rf ../etc; done", DENY),
        ("! cd /tmp || rm -rf ../etc", DENY),
        // Inside a loop, echo output may be piped at `done`: still checked.
        ("while true; do echo /etc/x; done", DENY),
        ("cd /tmp/research && rg foo src/", ALLOW),
        ("cd sub && cd - && ls", ALLOW),
        ("cd \"$(git rev-parse --show-toplevel)\" && rm -rf build", ALLOW),
    ]);
    check_bash(&config(true, &[]), &[
        ("cd sub && cat ../a.txt", ALLOW),
        ("cd /tmp && ls", DENY),
    ]);
    check_bash(&config(false, &["id_rsa*", "*.pem"]), &[
        ("cd ~/.ssh && cat id_rsa", DENY),
        ("cd keys && cat server.pem", DENY),
    ]);
}

#[test]
fn test_relative_paths_resolve_from_hook_cwd() {
    let tmp = TempDir::new().unwrap();
    let sub = tmp.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let ruleset = RuleSet::build(&config(true, &[]), tmp.path()).unwrap();
    // `../a.txt` from <root>/sub is <root>/a.txt — inside the project.
    let verdict = ruleset.evaluate(&input("Bash", json!({ "command": "cat ../a.txt" }), &sub));
    assert!(matches!(verdict, Verdict::Allow), "got {verdict:?}");
    let verdict = ruleset.evaluate(&input("Bash", json!({ "command": "cat ../../a.txt" }), &sub));
    assert!(matches!(verdict, Verdict::Deny(_)), "got {verdict:?}");
}

// ============================================================================
// S4: variables
// ============================================================================

#[test]
fn test_variables_assigned_in_the_command_are_expanded() {
    check_bash(&config(false, &[]), &[
        ("D=/; rm -rf $D*", DENY),
        ("D=/etc; cat $D/passwd", DENY),
        ("export D=/etc && cat \"$D/passwd\"", DENY),
        ("D='/*'; rm -rf $D", DENY),
        ("D=/etc bash -c 'cat $D/passwd'", DENY),
        ("export D=/etc; bash -c 'cat $D/passwd'", DENY),
        ("for d in /etc/*; do cat $d; done", DENY),
        // Not exported: the child shell sees an empty $D.
        ("D=/etc; bash -c 'cat $D/passwd'", ALLOW),
        // Single quotes: no expansion.
        ("D=/etc; cat '$D/passwd'", ALLOW),
        // Prefix assignment: `$D` is expanded with the old (unset) value.
        ("D=/etc cat $D/passwd", ALLOW),
    ]);
}

// ============================================================================
// F1: quoted glob characters are literal
// ============================================================================

#[test]
fn test_quoted_globs_are_literal() {
    check_bash(&config(false, &[]), &[
        ("printf '%s\\n' '/* Landing, slot 1 */' > h.css", ALLOW),
        ("git commit -m '/* fix */'", ALLOW),
        ("rg -n '/\\*\\*' src", ALLOW),
        ("rm -rf /\"*\"", ALLOW),
        ("sed 's/a/b/' a.css >> h.css\nprintf '%s\\n' \"/* today's stack */\" >> h.css", ALLOW),
        ("rm -rf /*", DENY),
        ("rm -rf \"/\"*", DENY),
        ("rm -rf /'x'*", DENY),
        ("bash -c 'rm -rf /*'", DENY),
        ("eval rm -rf '/*'", DENY),
        ("bash -c 'cat /{etc,var}/passwd'", DENY),
    ]);
    check_bash(&config(true, &[]), &[("printf '/* x */' > a.css", ALLOW)]);
}

// ============================================================================
// F2: inline code
// ============================================================================

#[test]
fn test_inline_code_string_operations_are_not_root_targets() {
    check_bash(&config(false, &[]), &[
        ("node -e 'const p = x.split(\"/\").pop()'", ALLOW),
        ("node -e 'x.replace(\"../../\", \"\")'", ALLOW),
        ("python3 -c 'print(\"/\".join(parts))'", ALLOW),
        ("python3 -c 'print(p.endswith(\"/\") or p == \"/\")'", ALLOW),
        ("node -e 'const s = a + \"/\" + b'", ALLOW),
        ("python3 -c 'p = \"src/usr/lib\"'", ALLOW),
        ("python3 -c \"import os; os.chdir('/')\"", DENY),
        ("python3 -c 'import subprocess; subprocess.run(c, cwd=\"/\")'", DENY),
        ("node -e 'require(\"fs\").readdirSync(\"/\")'", DENY),
        ("python3 -c 'open(\"//etc/passwd\")'", DENY),
        ("node -e 'readFileSync(\"../../../../../../../../../../etc/passwd\")'", DENY),
    ]);
}

// ============================================================================
// Phase 3: operands that are never paths
// ============================================================================

#[test]
fn test_text_operands_are_not_paths() {
    check_bash(&config(false, &[]), &[
        ("echo /", ALLOW),
        ("echo '/* ===== g-label.css ===== */'", ALLOW),
        ("tr '/' '_' < f.txt", ALLOW),
        ("cut -d / -f2 f.txt", ALLOW),
        ("awk -F '/' '{print $2}' f.txt", ALLOW),
        ("sed -n '/etc/p' notes.txt", ALLOW),
        ("sed -i '' 's/foo/bar/' src/a.ts", ALLOW),
        ("grep -rn \"/\" src", ALLOW),
        ("rg -n '/usr/local' docs", ALLOW),
        // Still checked:
        ("echo /*", DENY),
        ("echo / | xargs rm -rf", DENY),
        ("rm -rf $(echo /)", DENY),
        ("printf -v D '%s' /etc", DENY),
        ("sed -i '' 's/x/y/' /etc/hosts", DENY),
        ("sed -i '' -e 's/x/y/' /etc/hosts", DENY),
        ("rg --files /etc", DENY),
        ("grep -E 'a|b' /etc/passwd", DENY),
        ("grep -e foo /etc/passwd", DENY),
        ("rg -e foo -e bar /etc", DENY),
        ("rg -i foo /", DENY),
    ]);
}

#[test]
fn test_raw_devices_blocked_but_safe_devices_allowed() {
    check_bash(&config(false, &[]), &[
        ("echo x > /dev/disk2", DENY),
        ("dd if=img of=/dev/disk2", DENY),
        ("dd if=/dev/zero of=out.bin bs=1k count=1", ALLOW),
        ("ls > /dev/null 2>&1; echo hi > /dev/stderr", ALLOW),
    ]);
    check_bash(&config(true, &[]), &[
        ("curl -o /dev/null https://example.com", ALLOW),
        ("ls > /dev/null 2>&1", ALLOW),
    ]);
}

// ============================================================================
// S5: tools that run shell commands or open files
// ============================================================================

#[test]
fn test_monitor_command_is_checked_like_bash() {
    let tmp = TempDir::new().unwrap();
    let ruleset = RuleSet::build(&config(false, &[]), tmp.path()).unwrap();
    let deny = input("Monitor", json!({ "command": "rm -rf /*", "description": "x", "timeout_ms": 1000 }), tmp.path());
    assert!(matches!(ruleset.evaluate(&deny), Verdict::Deny(_)));
    let allow = input("Monitor", json!({ "command": "tail -f app.log", "description": "x", "timeout_ms": 1000 }), tmp.path());
    assert!(matches!(ruleset.evaluate(&allow), Verdict::Allow));
    let ws = input("Monitor", json!({ "ws": { "url": "wss://x" }, "description": "x", "timeout_ms": 1000 }), tmp.path());
    assert!(matches!(ruleset.evaluate(&ws), Verdict::Allow));
}

#[test]
fn test_lsp_file_path_is_checked() {
    let tmp = TempDir::new().unwrap();
    let ruleset = RuleSet::build(&config(false, &[".env"]), tmp.path()).unwrap();
    let lsp = |path: &str| {
        input("LSP", json!({ "operation": "hover", "filePath": path, "line": 1, "character": 1 }), tmp.path())
    };
    assert!(matches!(ruleset.evaluate(&lsp(".env")), Verdict::Deny(_)));
    assert!(matches!(ruleset.evaluate(&lsp("src/main.rs")), Verdict::Allow));
}

#[test]
fn test_current_builtin_tools_are_known() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = config(false, &[]);
    cfg.no_unknown_tools = true;
    let ruleset = RuleSet::build(&cfg, tmp.path()).unwrap();
    for tool in ["Agent", "ToolSearch", "SubagentHandback", "ScheduleWakeup", "ListAgents", "CronCreate", "EnterWorktree"] {
        let verdict = ruleset.evaluate(&input(tool, json!({}), tmp.path()));
        assert!(matches!(verdict, Verdict::Allow), "{tool}: {verdict:?}");
    }
}

// ============================================================================
// Heredocs / here-strings fed to a shell or interpreter are code
// ============================================================================

#[test]
fn test_heredoc_fed_to_shell_or_interpreter_is_checked() {
    check_bash(&config(false, &[]), &[
        ("bash <<'EOF'\nrm -rf /\nEOF", DENY),
        ("sh -s <<EOF\ncat /etc/passwd\nEOF", DENY),
        ("bash <<< 'rm -rf /*'", DENY),
        ("cd /tmp && bash <<'EOF'\nrm -rf ../etc\nEOF", DENY),
        ("python3 - <<'EOF'\nimport shutil; shutil.rmtree('/')\nEOF", DENY),
        ("python3 <<'EOF'\nprint(open('/etc/passwd').read())\nEOF", DENY),
        // Plain data on stdin is not code.
        ("cat > notes.md <<'EOF'\nrm -rf /\nEOF", ALLOW),
        ("python3 script.py <<'EOF'\n/etc/passwd\nEOF", ALLOW),
        ("bash -c 'cat' <<'EOF'\nrm -rf /\nEOF", ALLOW),
        ("bash <<'EOF'\necho done\nEOF", ALLOW),
    ]);
    // Under `-i`, stdin code is as unverifiable as `python3 -c`.
    check_bash(&config(true, &[]), &[("python3 - <<'EOF'\nprint(1)\nEOF", DENY)]);
}

// ============================================================================
// Review findings: regressions caught by an independent bypass review
// ============================================================================

#[test]
fn test_heredoc_inside_quoted_substitution_does_not_hide_the_rest() {
    check_bash(&config(false, &[]), &[
        ("git commit -m \"$(cat <<'EOF'\nfix: don't crash\nEOF\n)\" && git push && rm -rf /usr/local/lib/foo", DENY),
        ("gh pr create --body \"$(cat <<'EOF'\nDon't merge\nEOF\n)\" && echo done > /etc/hosts", DENY),
        ("git commit -m \"$(cat <<'EOF'\nAdd retry (max 3 attempts\nEOF\n)\" && rm -rf /", DENY),
        ("git commit -m \"$(cat <<'EOF'\n12\" pipes\nEOF\n)\" && rm -rf /", DENY),
        ("git commit -m \"$(cat <<'EOF'\nfix: don't crash (max 3\nEOF\n)\" && git push", ALLOW),
    ]);
    check_bash(&config(false, &[".env"]), &[
        ("git commit -m \"$(cat <<'EOF'\nuser's fix\nEOF\n)\" && cat .env", DENY),
    ]);
}

#[test]
fn test_arithmetic_shift_is_not_a_heredoc() {
    check_bash(&config(false, &[]), &[
        ("echo $((1<<2))\nrm -rf /", DENY),
        ("x=$((1<<20))\nrm -rf /*", DENY),
        ("echo $(( 1 << 2 ))\nrm -rf /", DENY),
        ("(( x <<= 1 ))\nrm -rf /", DENY),
        ("x=$((rm -rf /) )", DENY),
        ("echo $((1<<2)); echo ok", ALLOW),
    ]);
}

#[test]
fn test_echo_output_piped_through_compounds_and_nested_code() {
    check_bash(&config(false, &[]), &[
        ("{ echo /; } | xargs rm -rf", DENY),
        ("while true; do echo /; done | xargs rm -rf", DENY),
        ("for f in a b; do echo \"/etc/$f\"; done | xargs cat", DENY),
        ("if true; then echo /etc/hosts; fi | xargs cat", DENY),
        ("{ printf '%s\\n' /usr/local/foo; } | xargs rm -rf", DENY),
        ("bash -c 'echo /etc/hosts' | xargs cat", DENY),
        ("eval echo /etc/hosts | xargs cat", DENY),
    ]);
    check_bash(&config(true, &[]), &[("{ echo /tmp/x; } | xargs rm -rf", DENY)]);
}

#[test]
fn test_ampersand_and_noclobber_redirections() {
    check_bash(&config(false, &[]), &[
        ("echo hi >& /etc/x", DENY),
        ("printf 'x\\n' >& /etc/x", DENY),
        ("echo hi >&/etc/x", DENY),
        ("echo hi >| /etc/hosts", DENY),
        ("ls >&2", ALLOW),
        ("ls >& 2", ALLOW),
        ("make >& build.log", ALLOW),
    ]);
}

#[test]
fn test_path_builders_and_walkers_are_not_string_functions() {
    check_bash(&config(false, &[]), &[
        ("perl -MFile::Find -e 'find(sub { print }, \"/\")'", DENY),
        ("ruby -rfind -e 'Find.find(\"/\") { |f| puts f }'", DENY),
        ("python3 -c 'import os; os.listdir(os.path.join(\"/\"))'", DENY),
        ("python3 -c 'print(parts.join(\"/\") or s.find(\"/\"))'", ALLOW),
        ("python3 -c 'open(\"%s/etc/passwd\" % \"\")'", DENY),
    ]);
}

#[test]
fn test_sed_empty_script_and_dev_fd_traversal() {
    check_bash(&config(false, &[]), &[
        ("sed '' /etc/passwd", DENY),
        ("cat /dev/fd/../../etc/passwd", DENY),
        ("cd /dev/fd && rm -rf ../../*", DENY),
    ]);
    check_bash(&config(false, &[".env"]), &[("sed '' .env", DENY), ("sed -i '' 's/a/b/' .env", DENY)]);
}

#[test]
fn test_pathological_nesting_stays_fast() {
    // A slow hook can time out, and a timed-out hook doesn't block.
    let started = std::time::Instant::now();
    for cmd in ["$((".repeat(20000), "((".repeat(20000), "\"$(".repeat(10000), "((a) ".repeat(10000)] {
        let _ = clarg::bash_analyzer::extract_paths(&cmd);
    }
    assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
}
