//! Extraction-level checks for shell semantics: exact `raw` values and
//! the `unquoted_glob` flag.

use clarg::bash_analyzer::{PathContext, extract_paths, extract_paths_from};
use std::path::Path;

fn raws(cmd: &str) -> Vec<String> {
    extract_paths(cmd).into_iter().map(|p| p.raw).collect()
}

#[test]
fn test_unquoted_glob_flag() {
    let glob = |cmd: &str| extract_paths(cmd)[0].unquoted_glob;
    assert!(glob("rm -rf /*"));
    assert!(glob("rm -rf \"/\"*"));
    assert!(!glob("cat '/*'"));
    assert!(!glob("cat \"/*\""));
    assert!(!glob("cat /\\*"));
    assert!(!glob("cat /etc/hosts"));
}

#[test]
fn test_quoted_glob_raw_is_unmasked() {
    assert_eq!(raws("cat '/* x */'"), vec!["/* x */"]);
}

#[test]
fn test_relative_paths_after_cd_are_joined() {
    assert_eq!(raws("cd /tmp/x && cat a ../b"), vec!["/tmp/x", "/tmp/x/a", "/tmp/x/../b"]);
    assert_eq!(raws("cd sub && cat a"), vec!["sub", "sub/a"]);
    assert_eq!(raws("cat a && cd /tmp"), vec!["a", "/tmp"]);
    // A redirection on the `cd` itself applies before the change.
    assert_eq!(raws("cd /tmp > out.txt && cat a > b"), vec!["out.txt", "/tmp", "/tmp/b", "/tmp/a"]);
}

#[test]
fn test_redirection_after_cd_is_joined() {
    let paths = raws("cd /tmp/x && echo hi > out.txt");
    assert!(paths.contains(&"/tmp/x/out.txt".to_string()), "{paths:?}");
}

#[test]
fn test_unknown_cd_target_falls_back_to_start() {
    assert_eq!(raws("cd \"$UNSET_DIR_X\" && cat a"), vec!["$UNSET_DIR_X", "a"]);
}

#[test]
fn test_cd_dash_and_pushd_popd() {
    assert_eq!(raws("cd /tmp && cd /var && cd - && cat a"), vec!["/tmp", "/var", "-", "/tmp/a"]);
    assert_eq!(raws("pushd /tmp && popd && cat a"), vec!["/tmp", "a"]);
}

#[test]
fn test_cd_flags_are_skipped() {
    assert_eq!(raws("cd -P /"), vec!["/"]);
    assert_eq!(raws("cd -L -- /etc"), vec!["/etc"]);
}

#[test]
fn test_assigned_variables_are_expanded() {
    assert_eq!(raws("D=/etc; cat $D/passwd ${D}/hosts"), vec!["/etc/passwd", "/etc/hosts"]);
    assert_eq!(raws("export D=/etc; cat \"$D/x\""), vec!["/etc/x"]);
    assert_eq!(raws("D=/etc; cat '$D/x'"), vec!["$D/x"]);
    assert_eq!(raws("D=/etc cat $D/x"), vec!["$D/x"]);
    assert_eq!(raws("read D; cat $D/x"), vec!["$D/x"]);
}

#[test]
fn test_pwd_expands_from_start_dir() {
    let paths: Vec<String> = extract_paths_from("cat $PWD/a", Some(Path::new("/proj")))
        .into_iter()
        .map(|p| p.raw)
        .collect();
    assert_eq!(paths, vec!["/proj/a"]);
}

#[test]
fn test_substitution_bodies_are_extracted_and_rendered() {
    let paths = extract_paths("x=$(cat /etc/passwd); cat \"$(mktemp)\"");
    let raws: Vec<&str> = paths.iter().map(|p| p.raw.as_str()).collect();
    assert!(raws.contains(&"/etc/passwd"), "{raws:?}");
    assert!(raws.contains(&"$(…)"), "{raws:?}");
}

#[test]
fn test_bash_lc_is_a_command_string() {
    assert_eq!(raws("bash -lc 'cat /etc/passwd'"), vec!["/etc/passwd"]);
    assert_eq!(raws("bash -o pipefail -c 'cat /etc/passwd'"), vec!["/etc/passwd"]);
    let script = extract_paths("bash -o pipefail build.sh");
    assert_eq!(script[0].raw, "build.sh");
    assert!(matches!(script[0].context, PathContext::ExecTarget));
}

#[test]
fn test_inline_code_fragments_widen_to_tokens() {
    let refs = |cmd: &str| -> Vec<String> {
        extract_paths(cmd)
            .into_iter()
            .filter(|p| matches!(p.context, PathContext::InlineCodeRef { .. }))
            .map(|p| p.raw)
            .collect()
    };
    assert_eq!(refs("node -e 'x.replace(\"../../\", \"\")'"), vec!["../../"]);
    assert_eq!(refs("python3 -c 'p = \"src/usr/lib\"'"), vec!["src/usr/lib"]);
    assert_eq!(refs("python3 -c 'open(\"//etc/passwd\")'"), vec!["//etc/passwd"]);
    assert_eq!(refs("python3 -c 'open(f\"{base}/etc/x\")'"), vec!["/etc/x"]);
}

#[test]
fn test_rg_grep_pattern_is_not_a_path() {
    assert_eq!(raws("rg -n '/usr/local' docs"), vec!["docs"]);
    assert_eq!(raws("grep -A 3 -E pat /etc/hosts"), vec!["/etc/hosts"]);
    assert_eq!(raws("rg -e a -e b src lib"), vec!["src", "lib"]);
    assert_eq!(raws("rg --files /etc"), vec!["/etc"]);
    assert_eq!(raws("grep -rne foo /etc"), vec!["/etc"]);
}

#[test]
fn test_sed_script_operand_is_not_a_path() {
    assert_eq!(raws("sed '/etc/d' hosts.txt"), vec!["hosts.txt"]);
    assert_eq!(raws("sed -i '' 's/a/b/' f.txt"), vec!["f.txt"]);
    assert_eq!(raws("sed -n -e '/x/p' a b"), vec!["a", "b"]);
    assert_eq!(raws("sed -f /etc/script.sed f"), vec!["/etc/script.sed", "f"]);
}
