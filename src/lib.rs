//! LDAP server with REST API & file backends.
//!
//! Port of gorestldap: the server keeps the directory in memory, reloads it from
//! a backend (file or REST) on an interval or on demand, and answers LDAP
//! requests (bind, search, compare, modify) over BER.
//!
//! The crate denies `unsafe`: protocol parsing, TLS and HTTP all come from safe crates, and nothing
//! here needs to step outside them - with exactly one documented exception, `index_file`, where a
//! file is mapped. `deny` instead of `forbid` is what makes that exception expressible: `forbid`
//! cannot be lifted by an `allow` anywhere, and the alternative was a crate-wide permission for one
//! `unsafe` call in one module. Every other module is still checked, and the exception is named
//! where it lives rather than here.

#![deny(unsafe_code)]

pub mod acl;
pub mod ad_schema;
pub mod backend;
pub mod bootstrap;
pub mod catalog;
pub mod cldap;
pub mod cli;
pub mod cli_connection;
pub mod client;
pub mod config;
pub mod config_store;
pub mod danger;
pub mod directory;
pub mod dn;
pub mod http;
pub mod i18n;
pub mod import;
pub mod index;
pub mod index_check;
pub mod index_file;
pub mod integrity;
/// The KDC in this process: port 88, and the realm read out of this server's own directory.
///
/// Behind a feature rather than always built, because a directory that does not issue tickets should
/// not carry the code that can: the KDC engine is a dependency with its own crypto, and an operator
/// who has not asked for a realm should not be running one.
#[cfg(feature = "kdc")]
pub mod kerberos;
pub mod ldap;
pub mod ldif;
pub mod ldif_read;
pub mod limits;
pub mod logging;
pub mod mapping;
pub mod memory;
pub mod metrics;
pub mod model;
pub mod mutate;
pub mod operational;
pub mod pac_policy;
pub mod password;
pub mod peers;
pub mod prepare;
pub mod record_cache;
pub mod referral;
pub mod reload;
pub mod replication;
pub mod runtime;
pub mod sasl;
pub mod schema;
pub mod security;
pub mod server;
/// Security identifiers: the binary form AD stores, the text form Windows prints, and the rule that
/// a RID is handed out once.
pub mod sid;
/// SMB on port 445: the `IPC$` share a Samba member's join begins with.
///
/// Behind a feature for the same reason the KDC is: a directory that does not claim to be a domain
/// controller should not answer on the port one uses.
#[cfg(feature = "smb")]
pub mod smb;
pub mod tls;
pub mod yaml_export;
