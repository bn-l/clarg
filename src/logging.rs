use flexi_logger::{Cleanup, Criterion, FileSpec, Logger, LoggerHandle, Naming};
use std::path::{Path, PathBuf};

/// Returns the default log directory following the XDG Base Directory Specification.
/// Uses `$XDG_STATE_HOME/clarg` if set, otherwise `~/.local/state/clarg`.
pub fn default_log_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(xdg).join("clarg")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("clarg")
    } else {
        PathBuf::from("/tmp").join("clarg")
    }
}

/// Initialize the file logger with rotation.
///
/// Logs to `<dir>/clarg.log` with size-based rotation (1 MB, keep 3 old files).
/// If `log_dir_override` is `Some`, logs to that directory instead of the default.
///
/// Returns the logger handle (must be kept alive for logging to work).
/// Returns `None` if initialization fails (logging is best-effort).
pub fn init(log_dir_override: Option<&Path>) -> Option<LoggerHandle> {
    let log_dir = match log_dir_override {
        Some(dir) => dir.to_path_buf(),
        None => default_log_dir(),
    };

    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        eprintln!(
            "clarg: failed to create log directory {}: {e}",
            log_dir.display()
        );
        return None;
    }

    let symlink_path = log_dir.join("clarg.log");

    let result = Logger::try_with_str("debug").and_then(|logger| {
        logger
            .log_to_file(
                FileSpec::default()
                    .directory(&log_dir)
                    .basename("clarg")
                    .suppress_timestamp(),
            )
            .append()
            .rotate(
                Criterion::Size(1_000_000), // 1 MB
                Naming::Numbers,
                Cleanup::KeepLogFiles(3),
            )
            .create_symlink(symlink_path)
            .start()
    });

    match result {
        Ok(handle) => {
            log::debug!("logger initialized, writing to {}", log_dir.display());
            Some(handle)
        }
        Err(e) => {
            eprintln!("clarg: failed to initialize logger: {e}");
            None
        }
    }
}
