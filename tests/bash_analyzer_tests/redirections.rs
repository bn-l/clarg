use clarg::bash_analyzer::analyze;
use tempfile::TempDir;

// ============================================================================
// Allowed redirections (inside project)
// ============================================================================

#[test]
fn test_redirect_to_file_inside_project() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > output.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_append_inside_project() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello >> output.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_stderr_inside_project() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd 2> error.log";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_to_dev_null() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > /dev/null 2>&1";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_to_dev_zero() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > /dev/zero";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// Blocked redirections (outside project)
// ============================================================================

#[test]
fn test_redirect_to_absolute_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > /tmp/outside.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(result.unwrap().contains("redirection target"));
}

#[test]
fn test_redirect_to_etc() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_append_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello >> /tmp/log.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_stderr_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd 2> /tmp/error.log";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_combined_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd &> /tmp/all.log";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_with_tilde_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > ~/.bashrc";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_with_home_var_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > $HOME/.profile";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Multiple redirections
// ============================================================================

#[test]
fn test_multiple_redirects_all_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > out.txt 2> err.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_multiple_redirects_one_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd > out.txt 2> /tmp/err.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_redirect_relative_path_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > ./subdir/file.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_redirect_parent_dir_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hello > ../outside.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

// ============================================================================
// Quoted redirection targets
// ============================================================================

#[test]
fn test_redirect_double_quoted_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \"/tmp/out.txt\"";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "double-quoted external redirect should be blocked"
    );
    let reason = result.unwrap();
    assert!(
        reason.contains("/tmp/out.txt"),
        "deny reason should report the unquoted path, got: {reason}"
    );
}

#[test]
fn test_redirect_single_quoted_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > '/tmp/out.txt'";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "single-quoted external redirect should be blocked"
    );
}

#[test]
fn test_redirect_double_quoted_with_space_outside_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \"/tmp/out side.txt\"";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "quoted redirect with space should be blocked"
    );
    let reason = result.unwrap();
    assert!(
        reason.contains("/tmp/out side.txt"),
        "deny reason should contain the full spaced path, got: {reason}"
    );
}

#[test]
fn test_redirect_quoted_inside_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \"output with space.txt\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "quoted internal redirect should be allowed");
}

#[test]
fn test_redirect_unseparated_bare_outside_blocked() {
    // No space between `>` and the target: `>/tmp/x.txt`.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi >/tmp/out.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
}

#[test]
fn test_redirect_fd_redirect_not_treated_as_file() {
    // `2>&1` is fd-redirect, not a file redirect. Must not register a
    // spurious Redirection entry or try to resolve "&1" as a path.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cmd 2>&1";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

// ============================================================================
// Quote-aware tilde / $HOME handling in redirection targets
// ============================================================================
//
// Bash only does tilde expansion on a LEADING UNQUOTED `~`, and only
// expands `$HOME` when it is unquoted or inside double quotes without a
// preceding backslash. Redirection scanning must respect these rules
// (earlier work over-unquoted and home-expanded quoted literals like
// `'~/literal.txt'` and `"\$HOME/literal.txt"`, triggering false
// "outside project" denials).

#[test]
fn test_redirect_single_quoted_tilde_is_literal_and_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > '~/literal.txt'";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "single-quoted `~` should NOT be home-expanded, got deny: {:?}",
        result
    );
}

#[test]
fn test_redirect_double_quoted_tilde_is_literal_and_allowed() {
    // Bash does NOT do tilde expansion inside double quotes either.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \"~/literal.txt\"";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "double-quoted `~` should NOT be home-expanded, got deny: {:?}",
        result
    );
}

#[test]
fn test_redirect_escaped_tilde_outside_quotes_is_literal_and_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \\~/literal.txt";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "escaped `\\~` should NOT be home-expanded, got deny: {:?}",
        result
    );
}

#[test]
fn test_redirect_single_quoted_dollar_home_is_literal_and_allowed() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > '$HOME/literal.txt'";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "single-quoted `$HOME` should NOT be expanded, got deny: {:?}",
        result
    );
}

#[test]
fn test_redirect_escaped_dollar_in_double_quotes_is_literal_and_allowed() {
    // `"\$HOME/foo"` — the `\$` suppresses parameter expansion, so
    // bash writes to a literal filename `$HOME/foo`.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \"\\$HOME/literal.txt\"";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "escaped `\\$HOME` inside \"...\" should NOT be expanded, got deny: {:?}",
        result
    );
}

#[test]
fn test_redirect_double_quoted_dollar_home_still_expands_and_blocked() {
    // Bash DOES expand `$HOME` inside double quotes — make sure the
    // fix doesn't over-correct and silently allow this real leak.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > \"$HOME/steal.txt\"";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "double-quoted $HOME must still expand and be blocked"
    );
}

#[test]
fn test_redirect_unquoted_tilde_still_expands_and_blocked() {
    // Regression guard: the unquoted-tilde case must still be caught.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > ~/stolen.txt";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "unquoted `~/` redirect must still be blocked"
    );
}

#[test]
fn test_redirect_unquoted_dollar_home_still_expands_and_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > $HOME/stolen.txt";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "unquoted $HOME redirect must still be blocked"
    );
}

#[test]
fn test_redirect_unquoted_tilde_user_expands() {
    // `~root` as a known login name should still expand to the
    // platform root home and be blocked (since /var/root / /root is
    // outside the project).
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > ~root/.bashrc";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "unquoted `~root/` should still expand and block"
    );
}

#[test]
fn test_redirect_unquoted_tilde_plus_is_literal_and_allowed() {
    // `~+` is bash-special (=$PWD). It's not a login name, so it
    // falls through as literal; normalized against project_root that
    // lands inside the project — allowed.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo hi > ~+/output.txt";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "`~+` redirect must NOT synthesize /Users/+, got deny: {:?}",
        result
    );
}
