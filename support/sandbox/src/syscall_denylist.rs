// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform-specific configurable syscall denials.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

/// An error encountered while loading a syscall denylist.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyscallDenylistError {
    /// The current platform does not use a syscall denylist.
    #[error("syscall denylists are not supported on this platform")]
    UnsupportedPlatform,

    /// The denylist file could not be read.
    #[error("failed to read syscall denylist {path}")]
    Read {
        /// The denylist path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The denylist file did not contain valid JSON.
    #[error("failed to parse syscall denylist {path}")]
    Parse {
        /// The denylist path.
        path: PathBuf,
        /// The underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// The denylist contained an empty syscall name.
    #[error("syscall denylist {path} contains an empty name at index {index}")]
    EmptyName {
        /// The denylist path.
        path: PathBuf,
        /// The zero-based array index.
        index: usize,
    },

    /// The denylist contained the same syscall more than once.
    #[error("syscall denylist {path} contains duplicate syscall {name:?}")]
    Duplicate {
        /// The denylist path.
        path: PathBuf,
        /// The duplicated syscall name.
        name: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyscallDenylist {
    #[serde(default, rename = "description")]
    _description: Option<String>,
    denied_syscalls: Vec<String>,
}

/// Return the source-tree configuration path for the current platform.
pub fn platform_syscall_denylist_path() -> Result<PathBuf, SyscallDenylistError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("unix")
            .join("syscall_denylist.json"))
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err(SyscallDenylistError::UnsupportedPlatform)
    }
}

/// Load and validate syscall names from `path`.
pub fn load_syscall_denylist(path: impl AsRef<Path>) -> Result<Vec<String>, SyscallDenylistError> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|source| SyscallDenylistError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let config: SyscallDenylist =
        serde_json::from_str(&contents).map_err(|source| SyscallDenylistError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    let mut names = BTreeSet::new();
    for (index, name) in config.denied_syscalls.into_iter().enumerate() {
        let name = name.trim();
        if name.is_empty() {
            return Err(SyscallDenylistError::EmptyName {
                path: path.to_path_buf(),
                index,
            });
        }
        if !names.insert(name.to_string()) {
            return Err(SyscallDenylistError::Duplicate {
                path: path.to_path_buf(),
                name: name.to_string(),
            });
        }
    }

    Ok(names.into_iter().collect())
}

/// Load the syscall denylist selected for the current platform.
pub fn load_platform_syscall_denylist() -> Result<Vec<String>, SyscallDenylistError> {
    load_syscall_denylist(platform_syscall_denylist_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_sorted_syscall_names() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            temp.path(),
            r#"{"denied_syscalls":["socket","accept4","bind"]}"#,
        )
        .unwrap();

        assert_eq!(
            load_syscall_denylist(temp.path()).unwrap(),
            ["accept4", "bind", "socket"].map(str::to_string)
        );
    }

    #[test]
    fn rejects_duplicate_syscall_names() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), r#"{"denied_syscalls":["socket","socket"]}"#).unwrap();

        assert!(matches!(
            load_syscall_denylist(temp.path()),
            Err(SyscallDenylistError::Duplicate { .. })
        ));
    }
}
