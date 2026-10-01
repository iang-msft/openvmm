// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform-specific configurable syscall denials.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

/// Whether denying a syscall is required or workload-dependent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyscallDenylistClassification {
    /// The syscall must remain denied.
    Mandatory,
    /// The syscall may be allowed when profiling demonstrates a workload need.
    Optional,
}

/// One configured syscall denial.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallDenylistEntry {
    /// Linux syscall name.
    pub name: String,
    /// Whether the denial is mandatory or optional.
    pub classification: SyscallDenylistClassification,
    /// Security rationale for denying the syscall.
    #[serde(default)]
    pub reason: Option<String>,
}

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
    denied_syscalls: Vec<SyscallDenylistEntry>,
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

/// Load and validate syscall denial entries from `path`.
pub fn load_syscall_denylist(
    path: impl AsRef<Path>,
) -> Result<Vec<SyscallDenylistEntry>, SyscallDenylistError> {
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
    let mut entries = BTreeMap::new();
    for (index, mut entry) in config.denied_syscalls.into_iter().enumerate() {
        let name = entry.name.trim().to_string();
        if name.is_empty() {
            return Err(SyscallDenylistError::EmptyName {
                path: path.to_path_buf(),
                index,
            });
        }
        entry.name = name.clone();
        entry.reason = entry
            .reason
            .map(|reason| reason.trim().to_string())
            .filter(|reason| !reason.is_empty());
        if entries.insert(entry.name.clone(), entry).is_some() {
            return Err(SyscallDenylistError::Duplicate {
                path: path.to_path_buf(),
                name,
            });
        }
    }

    Ok(entries.into_values().collect())
}

/// Load the syscall denylist selected for the current platform.
pub fn load_platform_syscall_denylist() -> Result<Vec<SyscallDenylistEntry>, SyscallDenylistError> {
    load_syscall_denylist(platform_syscall_denylist_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_sorted_syscall_entries() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            temp.path(),
            r#"{
                "denied_syscalls": [
                    {"name":"socket","classification":"mandatory","reason":" Network access. "},
                    {"name":"accept4","classification":"optional"},
                    {"name":"bind","classification":"mandatory","reason":""}
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(
            load_syscall_denylist(temp.path()).unwrap(),
            [
                SyscallDenylistEntry {
                    name: "accept4".to_string(),
                    classification: SyscallDenylistClassification::Optional,
                    reason: None,
                },
                SyscallDenylistEntry {
                    name: "bind".to_string(),
                    classification: SyscallDenylistClassification::Mandatory,
                    reason: None,
                },
                SyscallDenylistEntry {
                    name: "socket".to_string(),
                    classification: SyscallDenylistClassification::Mandatory,
                    reason: Some("Network access.".to_string()),
                },
            ]
        );
    }

    #[test]
    fn rejects_duplicate_syscall_names() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            temp.path(),
            r#"{
                "denied_syscalls": [
                    {"name":"socket","classification":"mandatory"},
                    {"name":"socket","classification":"optional"}
                ]
            }"#,
        )
        .unwrap();

        assert!(matches!(
            load_syscall_denylist(temp.path()),
            Err(SyscallDenylistError::Duplicate { .. })
        ));
    }

    #[test]
    fn rejects_unknown_classification() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            temp.path(),
            r#"{
                "denied_syscalls": [
                    {"name":"socket","classification":"recommended"}
                ]
            }"#,
        )
        .unwrap();

        assert!(matches!(
            load_syscall_denylist(temp.path()),
            Err(SyscallDenylistError::Parse { .. })
        ));
    }
}
