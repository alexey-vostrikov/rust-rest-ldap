//! LDAP server with REST API & file backends.
//!
//! Port of gorestldap: the server keeps the directory in memory, reloads it from
//! a backend (file or REST) on an interval or on demand, and answers LDAP
//! requests (bind, search, compare, modify) over BER.

pub mod cli;
pub mod config;
pub mod dn;
pub mod model;
pub mod ssha;
