use clarg::bash_analyzer::split_shell_operators;

// ============================================================================
// Single command (no operators)
// ============================================================================

#[test]
fn test_split_simple_command() {
    let result = split_shell_operators("ls -la");
    assert_eq!(result, vec!["ls -la"]);
}

#[test]
fn test_split_empty_string() {
    let result = split_shell_operators("");
    assert!(result.is_empty());
}

#[test]
fn test_split_whitespace_only() {
    let result = split_shell_operators("   ");
    assert!(result.is_empty());
}

// ============================================================================
// Semicolon (;)
// ============================================================================

#[test]
fn test_split_semicolon() {
    let result = split_shell_operators("cmd1; cmd2");
    assert_eq!(result, vec!["cmd1", " cmd2"]);
}

#[test]
fn test_split_multiple_semicolons() {
    let result = split_shell_operators("cmd1; cmd2; cmd3");
    assert_eq!(result, vec!["cmd1", " cmd2", " cmd3"]);
}

#[test]
fn test_split_semicolon_no_space() {
    let result = split_shell_operators("cmd1;cmd2");
    assert_eq!(result, vec!["cmd1", "cmd2"]);
}

// ============================================================================
// AND operator (&&)
// ============================================================================

#[test]
fn test_split_and_operator() {
    let result = split_shell_operators("cmd1 && cmd2");
    assert_eq!(result, vec!["cmd1 ", " cmd2"]);
}

#[test]
fn test_split_multiple_and_operators() {
    let result = split_shell_operators("cmd1 && cmd2 && cmd3");
    assert_eq!(result, vec!["cmd1 ", " cmd2 ", " cmd3"]);
}

#[test]
fn test_split_and_no_spaces() {
    let result = split_shell_operators("cmd1&&cmd2");
    assert_eq!(result, vec!["cmd1", "cmd2"]);
}

// ============================================================================
// OR operator (||)
// ============================================================================

#[test]
fn test_split_or_operator() {
    let result = split_shell_operators("cmd1 || cmd2");
    assert_eq!(result, vec!["cmd1 ", " cmd2"]);
}

#[test]
fn test_split_multiple_or_operators() {
    let result = split_shell_operators("cmd1 || cmd2 || cmd3");
    assert_eq!(result, vec!["cmd1 ", " cmd2 ", " cmd3"]);
}

// ============================================================================
// Pipe (|)
// ============================================================================

#[test]
fn test_split_pipe() {
    let result = split_shell_operators("cmd1 | cmd2");
    assert_eq!(result, vec!["cmd1 ", " cmd2"]);
}

#[test]
fn test_split_multiple_pipes() {
    let result = split_shell_operators("cmd1 | cmd2 | cmd3");
    assert_eq!(result, vec!["cmd1 ", " cmd2 ", " cmd3"]);
}

// ============================================================================
// Mixed operators
// ============================================================================

#[test]
fn test_split_mixed_and_or() {
    let result = split_shell_operators("cmd1 && cmd2 || cmd3");
    assert_eq!(result, vec!["cmd1 ", " cmd2 ", " cmd3"]);
}

#[test]
fn test_split_mixed_pipe_and_semicolon() {
    let result = split_shell_operators("cmd1 | cmd2; cmd3");
    assert_eq!(result, vec!["cmd1 ", " cmd2", " cmd3"]);
}

#[test]
fn test_split_all_operators() {
    let result = split_shell_operators("cmd1 && cmd2 || cmd3 | cmd4; cmd5");
    assert_eq!(result, vec!["cmd1 ", " cmd2 ", " cmd3 ", " cmd4", " cmd5"]);
}

// ============================================================================
// Quoted strings (operators inside quotes are not split)
// ============================================================================

#[test]
fn test_split_double_quoted_semicolon() {
    let result = split_shell_operators("echo \"hello; world\"");
    assert_eq!(result, vec!["echo \"hello; world\""]);
}

#[test]
fn test_split_single_quoted_semicolon() {
    let result = split_shell_operators("echo 'hello; world'");
    assert_eq!(result, vec!["echo 'hello; world'"]);
}

#[test]
fn test_split_double_quoted_and() {
    let result = split_shell_operators("echo \"cmd1 && cmd2\"");
    assert_eq!(result, vec!["echo \"cmd1 && cmd2\""]);
}

#[test]
fn test_split_single_quoted_pipe() {
    let result = split_shell_operators("echo 'cmd1 | cmd2'");
    assert_eq!(result, vec!["echo 'cmd1 | cmd2'"]);
}

#[test]
fn test_split_mixed_quotes_and_operators() {
    let result = split_shell_operators("echo \"a;b\" && echo 'c|d'");
    assert_eq!(result, vec!["echo \"a;b\" ", " echo 'c|d'"]);
}

// ============================================================================
// Escaped characters
// ============================================================================

#[test]
fn test_split_escaped_semicolon() {
    let result = split_shell_operators("echo hello\\; world");
    assert_eq!(result, vec!["echo hello\\; world"]);
}

#[test]
fn test_split_escaped_ampersand() {
    let result = split_shell_operators("echo hello\\&\\& world");
    assert_eq!(result, vec!["echo hello\\&\\& world"]);
}

#[test]
fn test_split_escaped_pipe() {
    let result = split_shell_operators("echo hello\\| world");
    assert_eq!(result, vec!["echo hello\\| world"]);
}

// ============================================================================
// Complex real-world examples
// ============================================================================

#[test]
fn test_split_cd_and_ls() {
    let result = split_shell_operators("cd /tmp && ls -la");
    assert_eq!(result, vec!["cd /tmp ", " ls -la"]);
}

#[test]
fn test_split_mkdir_and_cd() {
    let result = split_shell_operators("mkdir -p dir && cd dir && touch file");
    assert_eq!(result, vec!["mkdir -p dir ", " cd dir ", " touch file"]);
}

#[test]
fn test_split_grep_pipe_chain() {
    let result = split_shell_operators("cat file | grep pattern | wc -l");
    assert_eq!(result, vec!["cat file ", " grep pattern ", " wc -l"]);
}

#[test]
fn test_split_test_and_exec() {
    let result = split_shell_operators("test -f file && rm file || echo 'not found'");
    assert_eq!(result, vec!["test -f file ", " rm file ", " echo 'not found'"]);
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_split_single_ampersand() {
    // Background `&` ends the command (trailing empty part dropped).
    let result = split_shell_operators("cmd &");
    assert_eq!(result, vec!["cmd "]);
}

#[test]
fn test_split_ampersand_at_end() {
    let result = split_shell_operators("cmd1 && cmd2 &");
    assert_eq!(result, vec!["cmd1 ", " cmd2 "]);
}

#[test]
fn test_split_background_ampersand_between_commands() {
    let result = split_shell_operators("python3 x.py & cat /etc/passwd");
    assert_eq!(result, vec!["python3 x.py ", " cat /etc/passwd"]);
}

#[test]
fn test_split_fd_redirections_keep_ampersand() {
    assert_eq!(split_shell_operators("ls 2>&1"), vec!["ls 2>&1"]);
    assert_eq!(split_shell_operators("ls &> out"), vec!["ls &> out"]);
    assert_eq!(split_shell_operators("ls &>> out"), vec!["ls &>> out"]);
    assert_eq!(split_shell_operators("ls >&2"), vec!["ls >&2"]);
    assert_eq!(split_shell_operators("cat <&0"), vec!["cat <&0"]);
}

#[test]
fn test_split_pipe_ampersand() {
    let result = split_shell_operators("make |& tee log");
    assert_eq!(result, vec!["make ", " tee log"]);
}

#[test]
fn test_split_unquoted_newline() {
    let result = split_shell_operators("cd src\nrm -rf /");
    assert_eq!(result, vec!["cd src", "rm -rf /"]);
}

#[test]
fn test_split_quoted_newline_kept() {
    let result = split_shell_operators("echo 'a\nb'\nls");
    assert_eq!(result, vec!["echo 'a\nb'", "ls"]);
}

#[test]
fn test_split_line_continuation_kept() {
    let result = split_shell_operators("cat a \\\n  b");
    assert_eq!(result, vec!["cat a \\\n  b"]);
}

#[test]
fn test_split_with_ops_reports_pipe() {
    use clarg::bash_analyzer::{Separator, split_shell_operators_with_ops};
    let result = split_shell_operators_with_ops("echo / | xargs rm; ls");
    let seps: Vec<Separator> = result.iter().map(|(_, s)| *s).collect();
    assert_eq!(seps, vec![Separator::Pipe, Separator::Other, Separator::Other]);
}

#[test]
fn test_split_nested_quotes() {
    let result = split_shell_operators("echo \"it's a 'test'\" && echo done");
    assert_eq!(result, vec!["echo \"it's a 'test'\" ", " echo done"]);
}

#[test]
fn test_split_unmatched_quote_handled() {
    // Unmatched quote - split still works
    let result = split_shell_operators("echo \"hello; cmd2");
    // The ; is inside the unclosed quote, so no split
    assert_eq!(result, vec!["echo \"hello; cmd2"]);
}
