//! `file` backend: users and groups come from two JSON files.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{BackendError, DirectoryData, EntryChange};

/// Configuration of the file backend (`backends.file` section).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FileBackendConfig {
    pub users_path: PathBuf,
    pub groups_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct FileBackend {
    users_path: PathBuf,
    groups_path: PathBuf,
}

impl FileBackend {
    pub fn from_config(config: &serde_yaml_ng::Value) -> Result<Self, BackendError> {
        let config: FileBackendConfig = serde_yaml_ng::from_value(config.clone())
            .map_err(|err| BackendError::InvalidConfig(err.to_string()))?;
        Ok(Self::new(config.users_path, config.groups_path))
    }

    pub fn new(users_path: PathBuf, groups_path: PathBuf) -> Self {
        Self {
            users_path,
            groups_path,
        }
    }

    pub fn load(&self) -> Result<DirectoryData, BackendError> {
        Ok(DirectoryData {
            users: read_json(&self.users_path)?,
            groups: read_json(&self.groups_path)?,
        })
    }

    pub fn update(&self, change: &EntryChange) -> Result<(), BackendError> {
        match change {
            EntryChange::User { old, new } => {
                let mut users: Vec<crate::model::User> = read_json(&self.users_path)?;
                let position = users
                    .iter()
                    .position(|user| user == old.as_ref())
                    .ok_or(BackendError::EntryNotFound)?;
                users[position] = new.as_ref().clone();
                write_json(&self.users_path, &users)
            }
            EntryChange::Group { old, new } => {
                let mut groups: Vec<crate::model::Group> = read_json(&self.groups_path)?;
                let position = groups
                    .iter()
                    .position(|group| group == old.as_ref())
                    .ok_or(BackendError::EntryNotFound)?;
                groups[position] = new.as_ref().clone();
                write_json(&self.groups_path, &groups)
            }
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, BackendError> {
    let text = std::fs::read_to_string(path).map_err(|source| BackendError::Read {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| BackendError::Parse {
        path: path.display().to_string(),
        source,
    })
}

/// Writes through a temporary file in the same directory and renames it, so a
/// crash halfway cannot leave a truncated data file (gorestldap rewrote the file
/// in place).
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), BackendError> {
    let body = serde_json::to_string_pretty(value).map_err(|source| BackendError::Serialize {
        path: path.display().to_string(),
        source,
    })?;

    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, body + "\n").map_err(|source| BackendError::Write {
        path: tmp_path.display().to_string(),
        source,
    })?;
    std::fs::rename(&tmp_path, path).map_err(|source| BackendError::Write {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::User;
    use tempfile::tempdir;

    const USERS: &str = r#"[
        {
            "ldapAdmin": true,
            "objectClass": ["top", "inetOrgPerson"],
            "cn": "admin",
            "userPassword": "{SSHA}rapW2TNEFWp6HxD/nfwsjcBCD8Pi3Bvj",
            "uid": "admin",
            "mail": "admin@example.com"
        },
        {
            "objectClass": ["top", "inetOrgPerson"],
            "cn": "alice",
            "uid": "alice"
        }
    ]"#;

    const GROUPS: &str = r#"[
        {
            "objectClass": ["top", "posixGroup"],
            "cn": "group_a",
            "gidNumber": 2000,
            "memberUid": ["admin"]
        }
    ]"#;

    fn backend_with_data() -> (tempfile::TempDir, FileBackend) {
        let dir = tempdir().expect("tempdir");
        let users_path = dir.path().join("users.json");
        let groups_path = dir.path().join("groups.json");
        std::fs::write(&users_path, USERS).expect("users fixture");
        std::fs::write(&groups_path, GROUPS).expect("groups fixture");

        (dir, FileBackend::new(users_path, groups_path))
    }

    #[test]
    fn loads_users_and_groups_from_json_files() {
        let (_dir, backend) = backend_with_data();

        let data = backend.load().expect("load");

        assert_eq!(data.users.len(), 2);
        assert_eq!(data.users[0].cn, "admin");
        assert!(data.users[0].ldap_admin);
        assert_eq!(data.users[0].mail.as_deref(), Some("admin@example.com"));
        assert_eq!(data.groups.len(), 1);
        assert_eq!(data.groups[0].gid_number, Some(2000));
    }

    #[test]
    fn missing_file_names_the_path() {
        let dir = tempdir().expect("tempdir");
        let users_path = dir.path().join("absent.json");
        let backend = FileBackend::new(users_path.clone(), dir.path().join("groups.json"));

        let err = backend.load().expect_err("must fail");

        assert_eq!(
            err.to_string(),
            format!(
                "error reading '{}': No such file or directory (os error 2)",
                users_path.display()
            )
        );
    }

    #[test]
    fn broken_json_names_the_path() {
        let dir = tempdir().expect("tempdir");
        let users_path = dir.path().join("users.json");
        let groups_path = dir.path().join("groups.json");
        std::fs::write(&users_path, "{not json").expect("broken fixture");
        std::fs::write(&groups_path, "[]").expect("groups fixture");

        let err = FileBackend::new(users_path, groups_path)
            .load()
            .expect_err("must fail");

        assert!(
            err.to_string().contains("error parsing '") && err.to_string().contains("users.json"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn update_replaces_the_matching_user_and_keeps_the_others() {
        let (_dir, backend) = backend_with_data();
        let before = backend.load().expect("load");
        let mut updated = before.users[1].clone();
        updated.mail = Some("alice@example.com".to_string());

        backend
            .update(&EntryChange::User {
                old: Box::new(before.users[1].clone()),
                new: Box::new(updated.clone()),
            })
            .expect("update");

        let after = backend.load().expect("reload");
        assert_eq!(after.users.len(), 2);
        assert_eq!(after.users[0].cn, "admin");
        assert_eq!(after.users[1], updated);
    }

    #[test]
    fn update_of_unknown_user_is_rejected_and_leaves_the_file_untouched() {
        let (_dir, backend) = backend_with_data();
        let ghost = User {
            cn: "ghost".to_string(),
            ..User::default()
        };

        let err = backend
            .update(&EntryChange::User {
                old: Box::new(ghost.clone()),
                new: Box::new(ghost),
            })
            .expect_err("must fail");

        assert_eq!(err.to_string(), "entry not found in backend data");
        assert_eq!(backend.load().expect("reload").users.len(), 2);
    }

    #[test]
    fn update_writes_group_changes() {
        let (_dir, backend) = backend_with_data();
        let before = backend.load().expect("load");
        let mut updated = before.groups[0].clone();
        updated.member_uid = vec!["admin".to_string(), "alice".to_string()];

        backend
            .update(&EntryChange::Group {
                old: Box::new(before.groups[0].clone()),
                new: Box::new(updated.clone()),
            })
            .expect("update");

        assert_eq!(backend.load().expect("reload").groups[0], updated);
    }

    #[test]
    fn written_file_keeps_the_gorestldap_json_shape() {
        let (_dir, backend) = backend_with_data();
        let before = backend.load().expect("load");
        let mut updated = before.users[0].clone();
        updated.display_name = Some("Ivan Petrov".to_string());

        backend
            .update(&EntryChange::User {
                old: Box::new(before.users[0].clone()),
                new: Box::new(updated),
            })
            .expect("update");

        let text = std::fs::read_to_string(&backend.users_path).expect("read file");
        assert!(text.contains("\"displayName\": \"Ivan Petrov\""), "{text}");
        assert!(text.contains("\"ldapAdmin\": true"), "{text}");
        assert!(text.ends_with('\n'), "file should end with a newline");
        assert!(
            !backend.users_path.with_extension("json.tmp").exists(),
            "temporary file must be renamed away"
        );
    }

    #[test]
    fn config_section_is_parsed_into_paths() {
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            "users_path: examples/file/users.json\ngroups_path: examples/file/groups.json\n",
        )
        .expect("yaml");

        let backend = FileBackend::from_config(&config).expect("backend");

        assert_eq!(backend.users_path, Path::new("examples/file/users.json"));
        assert_eq!(backend.groups_path, Path::new("examples/file/groups.json"));
    }

    #[test]
    fn config_without_paths_is_rejected() {
        let config: serde_yaml_ng::Value =
            serde_yaml_ng::from_str("users_path: users.json").expect("yaml");

        let err = FileBackend::from_config(&config).expect_err("must reject");

        assert!(
            err.to_string()
                .starts_with("invalid backend configuration: "),
            "unexpected: {err}"
        );
    }

    #[test]
    fn example_files_from_the_repository_load() {
        let backend = FileBackend::new(
            PathBuf::from("examples/file/users.json"),
            PathBuf::from("examples/file/groups.json"),
        );

        let data = backend.load().expect("examples load");

        assert_eq!(data.users.len(), 1);
        assert_eq!(data.groups.len(), 3);
    }
}
