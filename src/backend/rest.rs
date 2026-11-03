//! `rest` backend: users and groups come from an HTTP service.
//!
//! The shape is gorestldap's: `url` plus a path for users and one for groups, an
//! `Authorization: Token <token>` header, and a timeout. What it reads is a JSON array of users
//! and one of groups; what it writes is one object at a time, named by its `cn` in the path.
//!
//! Three things this backend does differently, each for a reason.
//!
//! **It sends the whole object on a write.** gorestldap reflected over the struct and sent only
//! the fields that changed. That is `PATCH` semantics on a `PUT` request, and RFC 9110 §9.3.4
//! leaves a server free to treat the fields it did not receive as absent - the same request
//! against a stricter service would blank a user's other fields. The full object is what `PUT`
//! means, and the service sees one consistent picture.
//!
//! **It encodes the name in the path.** RFC 3986 does not allow a space or a slash in a path
//! segment, and a `cn` is user data: `cn=Doe, John` and `cn=a/b` both exist in real directories.
//! Unencoded, the first produces a malformed request and the second addresses a different
//! endpoint - the second is the dangerous one, because it looks like it worked.
//!
//! **It refuses redirects.** The client does not follow them at all: an `Authorization` header
//! sent to whoever answers a `3xx` is a token handed to an unexpected host.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::http::{Client, Endpoint};
use super::{BackendError, DirectoryData, EntryChange, ObjectKind};
use crate::client::Trust;
use crate::model::{Group, User};

/// How long a request may take when the configuration does not say.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration of the REST backend (`backends.rest` section).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RestBackendConfig {
    /// Base address of the service, with or without a path prefix.
    pub url: String,
    /// Path below `url` where the user collection lives.
    #[serde(default = "default_users_path")]
    pub users_path: String,
    /// Path below `url` where the group collection lives.
    #[serde(default = "default_groups_path")]
    pub groups_path: String,
    /// Sent as `Authorization: Token <value>`.
    pub auth_token: Option<String>,
    /// A duration such as `30s`; a request that takes longer is abandoned.
    pub http_request_timeout: Option<String>,
    /// Certificate authority for an `https` service, when it is not a public one.
    pub ca_file: Option<PathBuf>,
    /// Allow `DELETE <collection>/<name>` for entries removed from the directory.
    ///
    /// Off by default, and deliberately: the deletion endpoint is not part of the protocol
    /// gorestldap defined, so this is this server's guess at the service's shape. A service that
    /// does not implement it answers 404 or 405 and nothing is lost, but a service that
    /// implements it *differently* - a soft delete, say - should be found out by the operator
    /// turning this on, not by a directory that started deleting rows on its own.
    #[serde(default)]
    pub allow_delete: bool,
}

fn default_users_path() -> String {
    "/ldap/user".to_string()
}

fn default_groups_path() -> String {
    "/ldap/group".to_string()
}

/// The REST backend, cloneable so the enum of backends keeps its derives.
#[derive(Debug, Clone)]
pub struct RestBackend {
    client: Client,
    users_path: String,
    groups_path: String,
    allow_delete: bool,
}

impl RestBackend {
    pub fn from_config(config: &serde_json::Value) -> Result<Self, BackendError> {
        let config: RestBackendConfig = serde_json::from_value(config.clone())
            .map_err(|err| BackendError::InvalidConfig(err.to_string()))?;

        let endpoint = Endpoint::parse(&config.url)
            .map_err(|err| BackendError::InvalidConfig(err.to_string()))?;

        let timeout = match config.http_request_timeout.as_deref() {
            None => DEFAULT_TIMEOUT,
            Some(text) => humantime::parse_duration(text).map_err(|err| {
                BackendError::InvalidConfig(format!(
                    "'{text}' is not a duration for http_request_timeout: {err}"
                ))
            })?,
        };

        // A configured authority that cannot be read is a startup error: a service that is
        // silently trusted less (or more) than the operator wrote is worse than no start.
        let trust = match &config.ca_file {
            None => Trust::WebPki,
            Some(path) => {
                if !path.exists() {
                    return Err(BackendError::InvalidConfig(format!(
                        "ca_file '{}' does not exist",
                        path.display()
                    )));
                }
                Trust::File(path.clone())
            }
        };

        Ok(Self {
            client: Client::new(endpoint, config.auth_token, timeout, trust),
            users_path: config.users_path,
            groups_path: config.groups_path,
            allow_delete: config.allow_delete,
        })
    }

    /// The address this backend talks to, for the startup line.
    pub fn describe(&self) -> String {
        let endpoint = self.client.endpoint();
        format!(
            "{}://{}{}",
            if endpoint.secure { "https" } else { "http" },
            endpoint.authority(),
            endpoint.prefix
        )
    }

    /// Turns an HTTP failure into the error the server reports.
    ///
    /// The service address comes from the configuration, not from the request: an error naming
    /// only `/ldap/user/alice` leaves the operator looking through configurations for the
    /// service that answered.
    fn failure(&self, error: super::http::Error) -> BackendError {
        BackendError::Rest {
            url: self.describe(),
            detail: error.to_string(),
        }
    }

    pub async fn load(&self) -> Result<DirectoryData, BackendError> {
        let users: Vec<User> = self.read(&self.users_path).await?;
        let groups: Vec<Group> = self.read(&self.groups_path).await?;

        Ok(DirectoryData {
            users,
            groups,
            entries: Vec::new(),
        })
    }

    async fn read<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, BackendError> {
        let body = self
            .client
            .get(path)
            .await
            .map_err(|err| self.failure(err))?;

        serde_json::from_slice(&body).map_err(|source| BackendError::Parse {
            path: self.client.endpoint().target(path),
            source,
        })
    }

    pub async fn update(&self, change: &EntryChange) -> Result<(), BackendError> {
        match change {
            EntryChange::User { new, .. } => self.write(&self.users_path, &new.cn, new).await,
            EntryChange::Group { new, .. } => self.write(&self.groups_path, &new.cn, new).await,
            // What the write path actually produces: the directory holds entries, so a change
            // arrives as one. The object model of the service is smaller, so the entry is read
            // back into it - user or group by object class.
            EntryChange::Upsert { entry } => {
                if crate::mapping::is_group(entry) {
                    let group = crate::mapping::group_from_entry(entry)
                        .map_err(|err| BackendError::InvalidConfig(err.to_string()))?;
                    self.write(&self.groups_path, &group.cn, &group).await
                } else {
                    let user = crate::mapping::user_from_entry(entry)
                        .map_err(|err| BackendError::InvalidConfig(err.to_string()))?;
                    self.write(&self.users_path, &user.cn, &user).await
                }
            }
            EntryChange::Delete { dn, kind } => self.delete(dn, *kind).await,
        }
    }

    /// Removes the object the change names from the collection its kind belongs to.
    ///
    /// The kind comes from the caller, not from the DN: the DN's parent OU is this server's
    /// naming, which the backend is never told, and a service with separate user and group
    /// collections would otherwise get a DELETE aimed at the wrong one - deleting a group
    /// because a user of the same name was removed.
    async fn delete(&self, dn: &str, kind: Option<ObjectKind>) -> Result<(), BackendError> {
        if !self.allow_delete {
            return Err(BackendError::InvalidConfig(format!(
                "'{dn}' cannot be deleted through the REST backend: the service's delete \
                 endpoint is not part of the protocol this backend speaks. Set \
                 `allow_delete: true` if the service does implement `DELETE <collection>/<name>`,\
                 or delete it there; the redb backend deletes locally"
            )));
        }

        let Some(kind) = kind else {
            return Err(BackendError::InvalidConfig(format!(
                "'{dn}' cannot be deleted through the REST backend: which collection holds it \
                 was not established, and asking both would be a request nobody made"
            )));
        };

        let collection = match kind {
            ObjectKind::User => &self.users_path,
            ObjectKind::Group => &self.groups_path,
        };

        let name = name_of_dn(dn).ok_or_else(|| {
            BackendError::InvalidConfig(format!("'{dn}' has no name to address in the service"))
        })?;

        self.client
            .delete(&object_path(collection, &name))
            .await
            .map_err(|err| self.failure(err))?;

        Ok(())
    }

    async fn write<T: serde::Serialize>(
        &self,
        collection: &str,
        name: &str,
        value: &T,
    ) -> Result<(), BackendError> {
        let body = serde_json::to_vec(value).map_err(|source| BackendError::Serialize {
            path: collection.to_string(),
            source,
        })?;

        // `<collection>/<percent-encoded name>`: the name is user data and may contain a slash
        // or a space, and an unencoded slash would address a different endpoint.
        self.client
            .put(&object_path(collection, name), body)
            .await
            .map_err(|err| self.failure(err))?;
        Ok(())
    }
}

/// Percent-encodes everything in a path that RFC 3986 does not allow there.
///
/// Only the reserved characters and the ones a control or a space could be: the path of a
/// collection is written by an operator in a configuration file, and encoding it would be
/// surprising. This is applied to the last segment only - the object's name.
fn path_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());

    for byte in name.bytes() {
        match byte {
            // Unreserved (RFC 3986 §2.3): left alone so a plain name stays readable in a log.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }

    out
}

/// The path of one object: the collection as written, and the name encoded.
/// The name a DN carries: the value of its first RDN.
///
/// `cn=Doe\, John,ou=users,dc=example,dc=com` gives `Doe, John`. Handing the whole RDN to the
/// service would address an object named `cn=Doe, John`, which is not what the DN means.
fn name_of_dn(dn: &str) -> Option<String> {
    crate::dn::first_value(dn).map(|value| crate::dn::unescape(&value))
}

fn object_path(collection: &str, name: &str) -> String {
    format!(
        "{}/{}",
        collection.trim_end_matches('/'),
        path_segment(name)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_is_left_alone_so_it_stays_readable() {
        assert_eq!(path_segment("alice"), "alice");
        assert_eq!(path_segment("alice.smith-1_x~y"), "alice.smith-1_x~y");
    }

    #[test]
    fn a_name_with_a_slash_is_encoded_rather_than_addressing_another_endpoint() {
        // The dangerous case: unencoded, `a/b` would address `/ldap/user/a/b`, a different
        // resource, and the request would look like it succeeded.
        assert_eq!(path_segment("a/b"), "a%2Fb");
        assert_eq!(
            object_path("/ldap/user", "a/b"),
            "/ldap/user/a%2Fb",
            "only the name is encoded"
        );
    }

    #[test]
    fn a_name_with_a_space_or_a_comma_is_encoded() {
        assert_eq!(path_segment("Doe, John"), "Doe%2C%20John");
        // A non-ASCII name is encoded byte by byte, which is what UTF-8 in a URL means.
        assert_eq!(path_segment("Иван"), "%D0%98%D0%B2%D0%B0%D0%BD");
    }

    #[test]
    fn a_collection_path_keeps_its_own_characters() {
        assert_eq!(object_path("/ldap/user", "alice"), "/ldap/user/alice");
        assert_eq!(
            object_path("/api/v1/ldap-user/", "alice"),
            "/api/v1/ldap-user/alice",
            "hyphens in the collection are the operator's business, and a trailing slash is \
             not doubled"
        );
    }
}
