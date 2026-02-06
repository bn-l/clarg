use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct HookInput {
    pub session_id: String,
    pub transcript_path: Option<String>,
    pub cwd: PathBuf,
    pub permission_mode: Option<String>,
    pub hook_event_name: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    pub tool_use_id: Option<String>,
}

impl HookInput {
    /// Extract `tool_input.file_path` (used by Read, Write, Edit).
    pub fn file_path(&self) -> Option<&str> {
        self.tool_input.get("file_path").and_then(|v| v.as_str())
    }

    /// Extract `tool_input.command` (used by Bash).
    pub fn command(&self) -> Option<&str> {
        self.tool_input.get("command").and_then(|v| v.as_str())
    }

    /// Extract `tool_input.path` (used by Glob, Grep).
    pub fn search_path(&self) -> Option<&str> {
        self.tool_input.get("path").and_then(|v| v.as_str())
    }

    /// Extract `tool_input.pattern` (used by Glob).
    pub fn pattern(&self) -> Option<&str> {
        self.tool_input.get("pattern").and_then(|v| v.as_str())
    }

    /// Extract `tool_input.notebook_path` (used by NotebookEdit).
    pub fn notebook_path(&self) -> Option<&str> {
        self.tool_input
            .get("notebook_path")
            .and_then(|v| v.as_str())
    }
}
