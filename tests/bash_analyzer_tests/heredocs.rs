use clarg::bash_analyzer::{
    analyze, extract_paths, find_heredoc_spans, strip_heredocs,
};
use tempfile::TempDir;

// ============================================================================
// Original bug reproductions
// ============================================================================

#[test]
fn test_redirect_inside_heredoc_body_is_not_a_real_redirect() {
    // Original bug: a heredoc body containing a literal `> /` (e.g. a
    // markdown blockquote in a README) was scanned as a redirection
    // to filesystem root, tripping `no_root` / containment checks.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd =
        "cat > output.txt << 'EOF'\n# title\nthe bot writes to > / by default\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "heredoc body must not be scanned as shell, got deny: {:?}",
        result
    );
}

#[test]
fn test_root_in_heredoc_body_does_not_trigger_containment() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << 'EOF'\n> /etc/passwd\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "body `> /etc/passwd` must not register as a redirection target"
    );
}

#[test]
fn test_pipe_in_heredoc_body_does_not_split_command() {
    // `split_shell_operators` would otherwise split the body on `|`
    // and shlex the suffix as another command (e.g. `cat /etc/passwd`).
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << EOF\nfoo | cat /etc/passwd\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "pipe in body must not be parsed as a real shell pipe, got: {:?}",
        result
    );
}

// ============================================================================
// Same-line redirections must still be detected
// ============================================================================

#[test]
fn test_same_line_redirect_after_heredoc_op_still_blocked() {
    // `cat <<EOF > /tmp/out` is valid shell; the `> /tmp/out` is a
    // genuine external write that must survive heredoc stripping.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<EOF > /tmp/out\nbody\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "same-line external redirect must still be detected"
    );
    assert!(
        result.as_ref().unwrap().contains("/tmp/out"),
        "deny should mention the external path: {:?}",
        result
    );
}

#[test]
fn test_same_line_redirect_before_heredoc_op_still_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat > /tmp/out << EOF\nbody\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(result.is_some());
    assert!(
        result.as_ref().unwrap().contains("/tmp/out"),
        "deny should mention the external path: {:?}",
        result
    );
}

// ============================================================================
// Delimiter quoting variants
// ============================================================================

#[test]
fn test_heredoc_single_quoted_delim() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << 'EOF'\nsomething > /\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_heredoc_double_quoted_delim() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << \"EOF\"\n> /tmp/trap\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_heredoc_backslash_escaped_delim() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << \\EOF\n> /tmp/trap\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

// ============================================================================
// `<<-` tab-stripped delimiter matching
// ============================================================================

#[test]
fn test_heredoc_tab_stripped_closer_matches() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<-EOF\n\tbody with > /etc/passwd\n\tEOF";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "tab-indented EOF line must close <<-EOF body, got: {:?}",
        result
    );
}

#[test]
fn test_heredoc_tab_stripped_does_not_strip_spaces() {
    // <<- only strips leading TABS, not spaces. A space-indented
    // closing line is NOT a delimiter match (so we keep consuming).
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // The space-indented "EOF" doesn't close; only the bareword EOF does.
    let cmd = "cat <<-EOF\n\tbody\n   EOF\n\tEOF";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

// ============================================================================
// Multiple heredocs
// ============================================================================

#[test]
fn test_multiple_heredocs_same_line_strip_in_order() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<A <<B\n> /trap1\nA\n> /trap2\nB";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "both bodies must be stripped, got: {:?}",
        result
    );
}

#[test]
fn test_multiple_heredocs_separate_commands() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd =
        "cat << A\n> /etc\nA\ncat << B\n> /var\nB";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

// ============================================================================
// Unclosed heredoc — fail closed
// ============================================================================

#[test]
fn test_unclosed_heredoc_strips_to_end_of_input() {
    // Without a closing delimiter, every byte after the operator is
    // treated as body content and never scanned for shell syntax.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << EOF\n> /etc/passwd\nstill in body";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "unclosed heredoc body must not be scanned"
    );
}

// ============================================================================
// Here-strings (`<<<`)
// ============================================================================

#[test]
fn test_here_string_bareword_not_treated_as_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "here-string literal must not be interpreted as opening the file: {:?}",
        result
    );
}

#[test]
fn test_here_string_double_quoted_not_treated_as_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< \"/etc/passwd\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_here_string_single_quoted_not_treated_as_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< '/etc/passwd'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_here_string_followed_by_real_redirect_still_blocked() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< word > /tmp/out";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "real external redirect after a here-string must still fire"
    );
    assert!(result.as_ref().unwrap().contains("/tmp/out"));
}

// ============================================================================
// Recursion entry points (must run inside extract_paths_recursive too)
// ============================================================================

#[test]
fn test_heredoc_inside_bash_c_recursion_strips_body() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash -c 'cat << EOF\n> /\nEOF\n'";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "heredoc body inside bash -c must be stripped on recursion: {:?}",
        result
    );
}

#[test]
fn test_heredoc_inside_eval_recursion_strips_body() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "eval \"cat << EOF\n> /etc/passwd\nEOF\n\"";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "heredoc body inside eval must be stripped on recursion: {:?}",
        result
    );
}

#[test]
fn test_real_external_write_inside_bash_c_still_blocked() {
    // Defense in depth: the strip must NOT make us blind to a genuine
    // external redirect that the inner shell really does perform.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "bash -c 'cat > /tmp/leak << EOF\nbody\nEOF\n'";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "real external redirect inside bash -c must still be blocked"
    );
    assert!(result.as_ref().unwrap().contains("/tmp/leak"));
}

// ============================================================================
// Quote-state safety
// ============================================================================

#[test]
fn test_double_less_inside_quotes_is_not_a_heredoc() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "echo '<<not_a_heredoc'";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none());
}

#[test]
fn test_unbalanced_quote_in_heredoc_body_does_not_corrupt_following_command() {
    // A heredoc body with an unmatched `'` would otherwise leave the
    // top-level mask scanner stuck in single-quote mode, mis-masking
    // braces in following commands. With strip-before-mask, the body
    // is gone before masking ever sees it.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat << EOF\nit's a body\nEOF\necho hi > out.txt";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

// ============================================================================
// Direct unit tests on strip_heredocs / find_heredoc_spans
// ============================================================================

#[test]
fn test_strip_heredocs_no_op_when_no_doubleless() {
    let s = "echo hi > out.txt";
    assert_eq!(strip_heredocs(s), s);
}

#[test]
fn test_strip_heredocs_preserves_same_line_redirect() {
    let s = "cat <<EOF > /tmp/out\nbody\nEOF";
    let stripped = strip_heredocs(s);
    assert!(
        stripped.contains("> /tmp/out"),
        "same-line redirect must be preserved, got: {:?}",
        stripped
    );
    assert!(
        !stripped.contains("body"),
        "body must be stripped, got: {:?}",
        stripped
    );
    assert!(
        !stripped.contains("EOF"),
        "delimiter and closer must be stripped, got: {:?}",
        stripped
    );
}

#[test]
fn test_strip_heredocs_handles_unclosed_input_safely() {
    // Should not panic, should consume to end.
    let s = "cat << EOF\nstill body\n";
    let stripped = strip_heredocs(s);
    assert!(!stripped.contains("still body"));
}

#[test]
fn test_strip_heredocs_does_not_strip_triple_less_as_heredoc() {
    // `<<<word` is here-string, not a heredoc — and we still don't
    // want `word` to leak through as a tokenized path.
    let stripped = strip_heredocs("cat <<< /etc/passwd");
    assert!(!stripped.contains("/etc/passwd"));
}

#[test]
fn test_find_heredoc_spans_orders_op_and_body() {
    let cmd = "cat <<EOF\nbody\nEOF";
    let spans = find_heredoc_spans(cmd);
    assert_eq!(spans.len(), 2, "expected op + body span: {:?}", spans);
    assert!(spans[0].start < spans[1].start);
    assert!(spans[0].end <= spans[1].start);
}

#[test]
fn test_extract_paths_skips_heredoc_body_paths() {
    // Direct check: `extract_paths` must not surface body content as
    // a candidate path.
    let paths = extract_paths("cat << EOF\n/etc/passwd\nEOF");
    let raws: Vec<&str> = paths.iter().map(|p| p.raw.as_str()).collect();
    assert!(
        !raws.iter().any(|r| r.contains("/etc/passwd")),
        "body content leaked into extracted paths: {:?}",
        raws
    );
}

// ============================================================================
// Mixed-quoted delimiter words (bash quote-removes them to one literal)
// ============================================================================

#[test]
fn test_mixed_quoted_delim_does_not_hide_trailing_command() {
    // Regression: previously `<<E"OF"` was parsed as delim
    // `E"OF"`, which never matched the actual closing line `EOF`.
    // The stripper then consumed everything to end-of-input, hiding
    // any real command that followed the heredoc.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<E\"OF\"\nbody\nEOF\ncat /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "trailing `cat /etc/passwd` after a quote-removed delim must still be detected, got: {:?}",
        result
    );
    assert!(
        result.as_ref().unwrap().contains("/etc/passwd"),
        "deny should mention the trailing external read: {:?}",
        result
    );
}

#[test]
fn test_mixed_quoted_delim_strips_body_normally() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    // Body should be stripped — only delim form differs.
    let cmd = "cat <<E\"OF\"\n> /\nEOF";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_bare_quoted_bare_mixed_delim_resolves_correctly() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<E'O'F\nbody\nEOF\ncat /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "trailing command after E'O'F-delim heredoc must still fire: {:?}",
        result
    );
}

#[test]
fn test_quoted_then_bare_mixed_delim_resolves_correctly() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<\"EO\"F\nbody\nEOF\ncat /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "trailing command after \"EO\"F-delim heredoc must still fire: {:?}",
        result
    );
}

#[test]
fn test_escaped_then_bare_mixed_delim_resolves_correctly() {
    // `<<\EOF` quote-removes to `EOF`.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<\\EOF\nbody\nEOF\ncat /etc/passwd";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "trailing command after `<<\\EOF`-delim heredoc must still fire: {:?}",
        result
    );
}

// ============================================================================
// Here-strings with command/parameter substitutions and backticks
// ============================================================================

#[test]
fn test_here_string_with_command_substitution_strips_fully() {
    // Regression: previously the parser stopped at `(`, leaving
    // `/etc/passwd)` as a tokenized arg to cat.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< $(echo /etc/passwd)";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_none(),
        "here-string command-substitution must be fully stripped, got: {:?}",
        result
    );
}

#[test]
fn test_here_string_with_nested_command_substitution() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< $(echo $(date))";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_here_string_with_command_sub_then_real_redirect() {
    // The substitution is opaque-stripped, but a real `> /tmp/out`
    // sitting after it must still fire.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< $(echo word) > /tmp/out";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some(),
        "real `> /tmp/out` after `$(...)` here-string must still fire"
    );
    assert!(result.as_ref().unwrap().contains("/tmp/out"));
}

#[test]
fn test_here_string_with_parameter_expansion() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< ${HOME}";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_here_string_with_backtick_substitution() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< `date`";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_here_string_double_quoted_with_substitution_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< \"hi $(date)\"";
    let result = analyze(cmd, &project_root);
    assert!(result.is_none(), "got deny: {:?}", result);
}

#[test]
fn test_here_string_command_sub_with_inner_quoted_paren() {
    // `$(echo ")")` — the `)` inside the double-quoted segment is
    // literal, not a substitution closer.
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let cmd = "cat <<< $(echo \")\") > /tmp/out";
    let result = analyze(cmd, &project_root);
    assert!(
        result.is_some() && result.as_ref().unwrap().contains("/tmp/out"),
        "outer `> /tmp/out` must still be the surviving redirect, got: {:?}",
        result
    );
}
