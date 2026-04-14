use clarg::bash_analyzer::{expand_braces, extract_paths};

// ============================================================================
// expand_braces unit tests
// ============================================================================

#[test]
fn test_no_braces_passes_through() {
    assert_eq!(expand_braces("/etc/passwd"), vec!["/etc/passwd".to_string()]);
    assert_eq!(expand_braces("plain"), vec!["plain".to_string()]);
    assert_eq!(expand_braces(""), vec!["".to_string()]);
}

#[test]
fn test_simple_brace_expansion() {
    assert_eq!(
        expand_braces("/{etc,var}/passwd"),
        vec!["/etc/passwd".to_string(), "/var/passwd".to_string()]
    );
}

#[test]
fn test_brace_without_comma_passes_through() {
    // `{foo}` has no top-level comma → not a valid brace expansion
    assert_eq!(expand_braces("{foo}"), vec!["{foo}".to_string()]);
}

#[test]
fn test_range_expansion_passes_through() {
    // `{1..5}` range expansion is not supported, passes through unchanged
    assert_eq!(expand_braces("hello{1..5}"), vec!["hello{1..5}".to_string()]);
}

#[test]
fn test_unmatched_brace_passes_through() {
    assert_eq!(expand_braces("x{a,b"), vec!["x{a,b".to_string()]);
    assert_eq!(expand_braces("x}"), vec!["x}".to_string()]);
}

#[test]
fn test_empty_brace_parts_preserved() {
    // `{,b}` → "" and "b"
    assert_eq!(
        expand_braces("pre{,b}post"),
        vec!["prepost".to_string(), "prebpost".to_string()]
    );
}

#[test]
fn test_three_options() {
    assert_eq!(
        expand_braces("/{a,b,c}/x"),
        vec![
            "/a/x".to_string(),
            "/b/x".to_string(),
            "/c/x".to_string(),
        ]
    );
}

#[test]
fn test_cartesian_product() {
    // `{a,b}{c,d}` → ac, ad, bc, bd
    let got = expand_braces("{a,b}{c,d}");
    assert!(got.contains(&"ac".to_string()));
    assert!(got.contains(&"ad".to_string()));
    assert!(got.contains(&"bc".to_string()));
    assert!(got.contains(&"bd".to_string()));
    assert_eq!(got.len(), 4);
}

#[test]
fn test_nested_braces() {
    // `{a,{b,c}}` → a, b, c
    let got = expand_braces("{a,{b,c}}");
    assert!(got.contains(&"a".to_string()));
    assert!(got.contains(&"b".to_string()));
    assert!(got.contains(&"c".to_string()));
    assert_eq!(got.len(), 3);
}

#[test]
fn test_path_with_multiple_expansions() {
    // `/{etc,var}/{passwd,shadow}` → 4 paths
    let got = expand_braces("/{etc,var}/{passwd,shadow}");
    assert!(got.contains(&"/etc/passwd".to_string()));
    assert!(got.contains(&"/etc/shadow".to_string()));
    assert!(got.contains(&"/var/passwd".to_string()));
    assert!(got.contains(&"/var/shadow".to_string()));
    assert_eq!(got.len(), 4);
}

// ============================================================================
// extract_paths integration — brace-expanded tokens become multiple paths
// ============================================================================

#[test]
fn test_extract_paths_expands_brace_in_file_command() {
    let paths = extract_paths("cat /{etc,var}/passwd");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(raws.contains(&"/etc/passwd".to_string()), "got: {:?}", raws);
    assert!(raws.contains(&"/var/passwd".to_string()), "got: {:?}", raws);
}

#[test]
fn test_extract_paths_expands_brace_in_unknown_command() {
    // `ls` falls through to the UnknownCommandArg branch; braces should
    // still expand so downstream rules see each concrete path.
    let paths = extract_paths("ls /{tmp,usr}");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(raws.contains(&"/tmp".to_string()), "got: {:?}", raws);
    assert!(raws.contains(&"/usr".to_string()), "got: {:?}", raws);
}

#[test]
fn test_extract_paths_expands_brace_with_normalization_prep() {
    // `/tmp/../{etc,var}/passwd` expands first; normalize_path later
    // collapses the `..`. We only verify the expansion here.
    let paths = extract_paths("cat /tmp/../{etc,var}/passwd");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(
        raws.iter().any(|r| r == "/tmp/../etc/passwd"),
        "got: {:?}",
        raws
    );
    assert!(
        raws.iter().any(|r| r == "/tmp/../var/passwd"),
        "got: {:?}",
        raws
    );
}

#[test]
fn test_extract_paths_no_braces_passes_through_untouched() {
    let paths = extract_paths("cat /etc/passwd");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].raw, "/etc/passwd");
}

#[test]
fn test_extract_paths_expands_brace_in_redirection_target() {
    let paths = extract_paths("echo hi > /{etc,var}/out");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(
        raws.iter().any(|r| r == "/etc/out"),
        "got: {:?}",
        raws
    );
    assert!(
        raws.iter().any(|r| r == "/var/out"),
        "got: {:?}",
        raws
    );
}

// ============================================================================
// Quote-aware brace expansion (regression: braces inside quotes must
// NOT be treated as shell brace expansion)
// ============================================================================
//
// Bash does brace expansion BEFORE quote removal and ONLY on unquoted
// braces. Previously `extract_paths` brace-expanded tokens after
// `shlex` had already stripped quotes, so `cat '/{etc,var}'` falsely
// expanded to `/etc` and `/var`. These tests pin the correct behavior.

#[test]
fn test_single_quoted_braces_not_expanded_in_file_command() {
    let paths = extract_paths("cat '/{etc,var}/passwd'");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    // The literal filename survives — no `/etc/passwd` / `/var/passwd`.
    assert!(
        raws.iter().any(|r| r == "/{etc,var}/passwd"),
        "expected literal brace path, got: {:?}",
        raws
    );
    assert!(
        !raws.iter().any(|r| r == "/etc/passwd"),
        "quoted braces must NOT brace-expand, got: {:?}",
        raws
    );
    assert!(
        !raws.iter().any(|r| r == "/var/passwd"),
        "quoted braces must NOT brace-expand, got: {:?}",
        raws
    );
}

#[test]
fn test_double_quoted_braces_not_expanded_in_file_command() {
    let paths = extract_paths("cat \"/{etc,var}/passwd\"");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(
        raws.iter().any(|r| r == "/{etc,var}/passwd"),
        "expected literal brace path, got: {:?}",
        raws
    );
    assert!(
        !raws.iter().any(|r| r == "/etc/passwd"),
        "quoted braces must NOT brace-expand, got: {:?}",
        raws
    );
}

#[test]
fn test_escaped_braces_outside_quotes_not_expanded() {
    let paths = extract_paths("cat /\\{etc,var\\}/passwd");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    // Backslash-escaped braces outside quotes are literal too.
    assert!(
        raws.iter().any(|r| r == "/{etc,var}/passwd"),
        "expected literal brace path, got: {:?}",
        raws
    );
    assert!(
        !raws.iter().any(|r| r == "/etc/passwd"),
        "escaped braces must NOT brace-expand, got: {:?}",
        raws
    );
}

#[test]
fn test_quoted_braces_in_redirect_target_not_expanded() {
    let paths = extract_paths("echo hi > '/{etc,var}/out'");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(
        raws.iter().any(|r| r == "/{etc,var}/out"),
        "quoted redirect braces must survive, got: {:?}",
        raws
    );
    assert!(
        !raws.iter().any(|r| r == "/etc/out"),
        "quoted redirect braces must NOT expand, got: {:?}",
        raws
    );
}

#[test]
fn test_unquoted_braces_still_expand_alongside_quoted_ones() {
    // A single command with both a quoted brace literal AND an
    // unquoted brace group must expand ONLY the unquoted one.
    let paths = extract_paths("cat '/{keep,as,literal}' /{etc,var}/passwd");
    let raws: Vec<String> = paths.iter().map(|p| p.raw.clone()).collect();
    assert!(
        raws.iter().any(|r| r == "/{keep,as,literal}"),
        "quoted literal should survive, got: {:?}",
        raws
    );
    assert!(
        raws.iter().any(|r| r == "/etc/passwd"),
        "unquoted braces should still expand, got: {:?}",
        raws
    );
    assert!(
        raws.iter().any(|r| r == "/var/passwd"),
        "unquoted braces should still expand, got: {:?}",
        raws
    );
}

#[test]
fn test_quoted_set_literal_in_python_c_survives() {
    // Python set literal `{1,2,3}` inside a `-c` arg's single quotes
    // must survive masking and be reported to the user unchanged in
    // the inline-code deny message.
    use clarg::bash_analyzer::PathContext;
    let paths = extract_paths("python -c 'data = {1,2,3}; print(data)'");
    let exec = paths
        .iter()
        .find(|p| matches!(p.context, PathContext::InlineCodeExecution { .. }))
        .expect("expected InlineCodeExecution sentinel");
    let snippet = match &exec.context {
        PathContext::InlineCodeExecution { code_snippet, .. } => code_snippet.clone(),
        _ => unreachable!(),
    };
    assert!(
        snippet.contains("{1,2,3}"),
        "code_snippet must be unmasked, got: {}",
        snippet
    );
}
