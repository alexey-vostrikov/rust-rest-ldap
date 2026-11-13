//! The containers a domain has before anybody joins it.
//!
//! `cn=Computers` is not a convenience: a member's join searches for it by GUID
//! (`WKGUID=AA312825…`, see [`crate::ldap::wkguid`]) and adds its machine account there, so a
//! directory that answers the search with a DN that does not exist turns a join into
//! `The object name is not found`. A real domain creates this container with the domain itself, not
//! when the first machine arrives.
//!
//! Written at start rather than on demand, for the same reason the bootstrap administrator is:
//! `add` needs a parent, and the parent of every machine account is this one. A member cannot be
//! asked to create the branch it is about to hang from.
//!
//! # Not `OU`
//!
//! AD calls it `container` (1.2.840.113556.1.5.2) and puts it beside `CN=Users`, and a client that
//! reads `objectClass` expects that name. An `organizationalUnit` with a `cn=` RDN would answer the
//! search and then be the wrong kind of object to every reader that checks.

use crate::backend::{Backend, EntryChange};
use crate::model::{Attribute, Attributes, Entry};

/// The class of a plain container, `1.2.840.113556.1.5.2`.
pub const CONTAINER_CLASS: &str = "container";

/// The containers a domain root holds from the start, as DNs under `base_dn`.
pub fn containers(base_dn: &str) -> Vec<String> {
    vec![format!("cn=computers,{base_dn}")]
}

/// The configuration naming context: `cn=Configuration,<forest root>`.
///
/// Windows reads it before it joins. `NetpLdapGetLsaPrimaryDomain` takes the base from the root DSE's
/// `configurationNamingContext` and then reads `CN=Partitions`, where one `crossRef` per naming
/// context describes which DN answers for which DNS name. A directory that publishes no such context
/// leaves the client with no base to search at all, and it stops in `NetpGetNCData` with `0x37`
/// ("the specified network resource or device is no longer available") - measured on the AD-join
/// stand, where that was the last thing between a Windows Server 2022 and the domain.
///
/// This server keeps the partition inside the domain tree rather than beside it: for a
/// single-domain forest the two DNs coincide, and an implementation that hangs the partition from
/// the directory it already has answers every search the client makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// The domain naming context, as configured.
    pub base_dn: String,
    /// The DNS name of the domain, which is what a `crossRef` publishes as `dnsRoot`.
    pub dns_domain: String,
    /// The short name the `crossRef` is filed under, and the key of its RDN.
    pub netbios: String,
}

impl Partition {
    /// `cn=Configuration,<base_dn>`.
    pub fn dn(&self) -> String {
        format!("cn=Configuration,{}", self.base_dn)
    }

    /// What the domain's own `crossRef` is filed under.
    fn cross_ref_dn(&self) -> String {
        format!("cn={},cn=Partitions,{}", self.netbios, self.dn())
    }

    /// The entries of the partition, parents first.
    ///
    /// `systemFlags: 3` is what AD writes on the `crossRef` of a domain naming context (the two bits
    /// are "this is a naming context" and "it has no `msDS-NC-Replica-Locations`"), and a client that
    /// reads the flag to decide whether a context is writable here gets the same answer a real
    /// controller gives. The `dMD` entry is the schema container: this server keeps no schema
    /// partition, and a client that asks for one by name finds an object rather than nothing.
    pub fn entries(&self) -> Vec<Entry> {
        let mut configuration = Attributes::new()
            .push(Attribute::new(
                crate::model::ATTR_OBJECT_CLASS,
                vec!["top".to_string(), "configuration".to_string()],
            ))
            .push(Attribute::single("cn", "Configuration"));
        configuration = with_guid(configuration);
        let mut partitions = Attributes::new()
            .push(Attribute::new(
                crate::model::ATTR_OBJECT_CLASS,
                vec!["top".to_string(), "crossRefContainer".to_string()],
            ))
            .push(Attribute::single("cn", "Partitions"));
        partitions = with_guid(partitions);
        let mut cross_ref = Attributes::new()
            .push(Attribute::new(
                crate::model::ATTR_OBJECT_CLASS,
                vec!["top".to_string(), "crossRef".to_string()],
            ))
            .push(Attribute::single("cn", &self.netbios))
            // `nETBIOSName` is the attribute a client reads the domain's short name from - not `cn`,
            // which happens to hold the same text here. Measured on the AD-join stand:
            // `NetpGetNCData: Failed to read the NetBIOS name: 0x57` for a crossRef that carried
            // `cn` and `nCName` and nothing called `nETBIOSName`.
            .push(Attribute::single("nETBIOSName", &self.netbios))
            .push(Attribute::single("nCName", &self.base_dn))
            .push(Attribute::single("dnsRoot", &self.dns_domain))
            .push(Attribute::single("systemFlags", "3"));
        cross_ref = with_guid(cross_ref);
        let mut schema = Attributes::new()
            .push(Attribute::new(
                crate::model::ATTR_OBJECT_CLASS,
                vec!["top".to_string(), "dMD".to_string()],
            ))
            .push(Attribute::single("cn", "Schema"));
        schema = with_guid(schema);

        vec![
            Entry::new(self.dn(), configuration),
            Entry::new(format!("cn=Partitions,{}", self.dn()), partitions),
            Entry::new(self.cross_ref_dn(), cross_ref),
            Entry::new(format!("cn=Schema,{}", self.dn()), schema),
        ]
    }

    /// Creates the ones that are missing, and says which it created.
    pub async fn ensure(&self, backend: &Backend) -> Result<Vec<String>, String> {
        let existing: Vec<String> = backend
            .load()
            .await
            .map_err(|err| format!("the store could not be read: {err}"))?
            .entries
            .iter()
            .map(|entry| entry.dn().to_owned())
            .collect();

        let mut created = Vec::new();
        for entry in self.entries() {
            if existing
                .iter()
                .any(|have| have.eq_ignore_ascii_case(entry.dn()))
            {
                continue;
            }
            let dn = entry.dn().to_string();
            backend
                .apply(&[EntryChange::Upsert { entry }])
                .await
                .map_err(|err| format!("'{dn}' could not be created: {err}"))?;
            created.push(dn);
        }
        Ok(created)
    }
}

/// The domain object itself: the entry at the naming context's own DN.
///
/// AD keeps it as a `domainDNS` object and a client reads it as one - `NetpGetDomainData` asks for
/// `objectGuid` and `objectSid` on the domain DN and stops the join with `0x2` ("the system cannot
/// find the file specified") when the entry is not there. Measured on the AD-join stand, that was the
/// step after the NC data was finally readable.
///
/// The SID is the store's own domain SID, the one the accounts' SIDs are minted under: a domain
/// object carrying a different one would describe a domain that does not exist here.
pub fn domain_object(base_dn: &str, sid: &crate::sid::Sid, functionality: &str) -> Entry {
    // The RDN's own value, which is what `dc` has to say: `dc=ad,dc=example,dc=com` holds `ad`.
    let label = base_dn
        .split(',')
        .next()
        .and_then(|rdn| rdn.split_once('='))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default();

    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec![
                "top".to_string(),
                "domain".to_string(),
                "domainDNS".to_string(),
            ],
        ))
        .push(Attribute::single("dc", &label))
        // `Sid::attribute`, not a hand-built string: the value is base64 of the octets **and** the
        // attribute has to carry the binary flag, or the SID the schema validates is read out of
        // text - `a SID has revision 1, this one says 65` is the base64's first letter being taken
        // for a revision - and the attribute is dropped with the entry standing.
        .push(sid.attribute("objectSid"))
        // AD's default. A client reads it before it lets a non-administrator add a machine account,
        // and a domain object without it answers "the attribute is not there" for a join that has
        // otherwise been authorised.
        .push(Attribute::single("ms-DS-MachineAccountQuota", "10"))
        // Where a domain keeps its machine and user containers. A Windows client reads this before
        // it creates anything: with no value it cannot say where a computer account belongs, and the
        // path it takes instead is a DCERPC one that needs an endpoint mapper this server does not
        // publish - `NetpGetComputerObjectDn: Unable to bind to DS ... 0x6ba`, measured on the stand.
        // `B:32:` is AD's own spelling: a 32-digit GUID, no dashes, and the DN.
        .push(Attribute::new(
            "wellKnownObjects",
            vec![
                format!(
                    "B:32:{}:cn=computers,{base_dn}",
                    crate::ldap::wkguid::COMPUTERS
                ),
                format!("B:32:{}:ou=users,{base_dn}", crate::ldap::wkguid::USERS),
            ],
        ))
        // The domain's functional level, which a client reads from this object rather than from the
        // root DSE: `NetpGetDomainData` answers `0x2` for a domain object that does not say what
        // level it is.
        .push(Attribute::single("msDS-Behavior-Version", functionality));
    Entry::new(base_dn.to_string(), with_guid(attributes))
}

/// The `objectGUID` every object AD creates carries, left for the store to fill.
fn with_guid(attributes: Attributes) -> Attributes {
    attributes.push(Attribute::single(crate::model::ATTR_ENTRY_UUID, "").operational())
}

/// Creates the ones that are missing, and says which it created.
///
/// Missing is read from the store rather than assumed: a directory grown from an import already
/// has them, and a second `add` of the same DN would either be refused by the write path or, worse
/// on a backend that does not check, hold the entry twice.
pub async fn ensure_containers(backend: &Backend, base_dn: &str) -> Result<Vec<String>, String> {
    let data = backend
        .load()
        .await
        .map_err(|err| format!("the store could not be read: {err}"))?;
    let existing: Vec<String> = data
        .entries
        .iter()
        .map(|entry| entry.dn().to_owned())
        .collect();

    let mut created = Vec::new();
    for dn in containers(base_dn) {
        if existing.iter().any(|have| have.eq_ignore_ascii_case(&dn)) {
            continue;
        }
        backend
            .apply(&[EntryChange::Upsert {
                entry: container_entry(&dn),
            }])
            .await
            .map_err(|err| format!("'{dn}' could not be created: {err}"))?;
        created.push(dn);
    }
    Ok(created)
}

/// A container entry: the class AD uses, and the common name its RDN names.
pub fn container_entry(dn: &str) -> Entry {
    let label = dn
        .split_once(',')
        .map(|(first, _)| first)
        .unwrap_or(dn)
        .trim()
        .strip_prefix("cn=")
        .unwrap_or_default()
        .to_string();

    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), CONTAINER_CLASS.to_string()],
        ))
        .push(Attribute::single("cn", &label))
        .push(Attribute::single(crate::model::ATTR_ENTRY_UUID, "").operational());

    Entry::new(dn.to_string(), attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_domain_has_a_computers_container_from_the_start() {
        // The DN a member's WKGUID search resolves to, and the only one: a directory that names a
        // different container in the well-known table is resolved by that value instead.
        assert_eq!(
            containers("dc=example,dc=com"),
            vec!["cn=computers,dc=example,dc=com".to_string()]
        );
    }

    #[test]
    fn the_container_is_the_class_a_client_expects() {
        let entry = container_entry("cn=computers,dc=example,dc=com");

        assert_eq!(
            entry
                .attributes()
                .get(crate::model::ATTR_OBJECT_CLASS)
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["top".to_string(), "container".to_string()])
        );
        assert_eq!(
            entry
                .attributes()
                .get("cn")
                .map(|attribute| attribute.values.to_vec()),
            Some(vec!["computers".to_string()])
        );
    }
}
