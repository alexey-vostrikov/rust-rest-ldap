//! LDAP server with REST API & file backends.
//!
//! Port of gorestldap: the server keeps the directory in memory, reloads it from
//! a backend (file or REST) on an interval or on demand, and answers LDAP
//! requests (bind, search, compare, modify) over BER.
//!
//! The crate forbids `unsafe`: protocol parsing, TLS and HTTP all come from safe
//! crates, and nothing here needs to step outside them.

#![forbid(unsafe_code)]

pub mod acl;
pub mod backend;
pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod danger;
pub mod directory;
pub mod dn;
pub mod http;
pub mod i18n;
pub mod index;
pub mod integrity;
pub mod ldap;
pub mod ldif;
pub mod mapping;
pub mod metrics;
pub mod model;
pub mod mutate;
pub mod operational;
pub mod password;
pub mod reload;
pub mod schema;
pub mod security;
pub mod server;
pub mod tls;
pub mod yaml_export;
