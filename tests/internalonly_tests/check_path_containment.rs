use clarg::internalonly::check_path_containment;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Paths inside project (returns None)
// ============================================================================

#[test]
fn test_containment_exact_match_is_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = check_path_containment(&project_root, &project_root, "path");
    assert!(result.is_none());
}

#[test]
fn test_containment_child_is_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let child = project_root.join("src/main.rs");
    let result = check_path_containment(&child, &project_root, "path");
    assert!(result.is_none());
}

#[test]
fn test_containment_deeply_nested_is_inside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let child = project_root.join("a/b/c/d/e/f/file.txt");
    let result = check_path_containment(&child, &project_root, "path");
    assert!(result.is_none());
}

// ============================================================================
// Paths outside project (returns Some)
// ============================================================================

#[test]
fn test_containment_parent_is_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let parent = project_root.parent().unwrap();
    let result = check_path_containment(parent, &project_root, "path");
    assert!(result.is_some());
}

#[test]
fn test_containment_sibling_is_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let sibling = project_root.parent().unwrap().join("other-project");
    let result = check_path_containment(&sibling, &project_root, "path");
    assert!(result.is_some());
}

#[test]
fn test_containment_absolute_outside_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");
    let result = check_path_containment(outside, &project_root, "path");
    assert!(result.is_some());
}

#[test]
fn test_containment_root_is_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let result = check_path_containment(Path::new("/"), &project_root, "path");
    assert!(result.is_some());
}

// ============================================================================
// Reason message format
// ============================================================================

#[test]
fn test_containment_reason_contains_blocked_by_clarg() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");
    let reason = check_path_containment(outside, &project_root, "path").unwrap();
    assert!(reason.contains("Blocked by `clarg`"));
}

#[test]
fn test_containment_reason_contains_context() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");
    let reason = check_path_containment(outside, &project_root, "my context").unwrap();
    assert!(reason.contains("my context"));
}

#[test]
fn test_containment_reason_contains_target_path() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");
    let reason = check_path_containment(outside, &project_root, "path").unwrap();
    assert!(reason.contains("/etc/passwd"));
}

#[test]
fn test_containment_reason_contains_project_root() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");
    let reason = check_path_containment(outside, &project_root, "path").unwrap();
    assert!(reason.contains(project_root.to_str().unwrap()));
}

#[test]
fn test_containment_reason_contains_outside() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");
    let reason = check_path_containment(outside, &project_root, "path").unwrap();
    assert!(reason.contains("outside"));
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_containment_prefix_attack_blocked() {
    // A path that starts with project_root as a string prefix but is not a child
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let project_name = project_root.file_name().unwrap().to_str().unwrap();
    let attack_path = project_root
        .parent()
        .unwrap()
        .join(format!("{}-evil", project_name));

    let result = check_path_containment(&attack_path, &project_root, "path");
    assert!(result.is_some());
}

#[test]
fn test_containment_different_context_strings() {
    let tmp = TempDir::new().unwrap();
    let project_root = tmp.path().canonicalize().unwrap();
    let outside = Path::new("/etc/passwd");

    let contexts = vec![
        "path",
        "file_path",
        "'cd /tmp' would navigate to",
        "redirection target",
        "download output path",
    ];

    for context in contexts {
        let reason = check_path_containment(outside, &project_root, context).unwrap();
        assert!(reason.contains(context));
    }
}
