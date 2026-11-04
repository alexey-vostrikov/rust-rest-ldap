//! Schema: attribute types and object classes as data (RFC 4512).
//!
//! The syntax is the one operators already write for OpenLDAP, 389 DS and ApacheDS,
//! so an existing `schema` file can be dropped in unchanged:
//!
//! ```text
//! attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name
//!     EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
//!     SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
//!
//! objectclass ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL
//!     MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )
//! ```
//!
//! The schema is data, not code: adding an attribute type does not need a rebuild,
//! which is what makes the entry model from the previous step worth having. Parsing
//! is strict — an unknown keyword is an error, not a silently ignored token, because
//! a typo in `MUST` would otherwise disable a constraint without a trace.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::model::Entry;

/// Where a schema definition came from, for a message that names the source rather than the
/// symptom.
///
/// Separate from [`SchemaError`] because the parse failure is the same in every case and only
/// the address differs: a file has a path, a definition sent over the protocol has a position
/// and no path at all.
#[derive(Debug, Error)]
pub enum SchemaSource {
    #[error("error reading schema file '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("error loading schema from '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: SchemaError,
    },
    #[error("definition {position} added through cn=schema,cn=config is not usable: {source}")]
    Definition {
        position: usize,
        #[source]
        source: SchemaError,
    },
}

/// Value syntaxes that the validator understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// UTF-8 text, case-insensitive matching (most names).
    DirectoryString,
    /// ASCII text (mail, DNS names).
    Ia5String,
    /// Decimal integer.
    Integer,
    /// `TRUE` or `FALSE`.
    Boolean,
    /// Arbitrary bytes, base64 in LDIF.
    OctetString,
    /// A DN.
    DistinguishedName,
    /// An object identifier.
    Oid,
    /// `YYYYmmddHHMMSSZ` (generalized time).
    GeneralizedTime,
}

impl Syntax {
    /// Syntax OID (RFC 4517) as written in a definition.
    pub fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.3.6.1.4.1.1466.115.121.1.15" => Some(Syntax::DirectoryString),
            "1.3.6.1.4.1.1466.115.121.1.26" => Some(Syntax::Ia5String),
            "1.3.6.1.4.1.1466.115.121.1.27" => Some(Syntax::Integer),
            "1.3.6.1.4.1.1466.115.121.1.7" => Some(Syntax::Boolean),
            "1.3.6.1.4.1.1466.115.121.1.40" => Some(Syntax::OctetString),
            "1.3.6.1.4.1.1466.115.121.1.12" => Some(Syntax::DistinguishedName),
            "1.3.6.1.4.1.1466.115.121.1.38" => Some(Syntax::Oid),
            "1.3.6.1.4.1.1466.115.121.1.24" => Some(Syntax::GeneralizedTime),
            _ => None,
        }
    }

    pub fn oid(&self) -> &'static str {
        match self {
            Syntax::DirectoryString => "1.3.6.1.4.1.1466.115.121.1.15",
            Syntax::Ia5String => "1.3.6.1.4.1.1466.115.121.1.26",
            Syntax::Integer => "1.3.6.1.4.1.1466.115.121.1.27",
            Syntax::Boolean => "1.3.6.1.4.1.1466.115.121.1.7",
            Syntax::OctetString => "1.3.6.1.4.1.1466.115.121.1.40",
            Syntax::DistinguishedName => "1.3.6.1.4.1.1466.115.121.1.12",
            Syntax::Oid => "1.3.6.1.4.1.1466.115.121.1.38",
            Syntax::GeneralizedTime => "1.3.6.1.4.1.1466.115.121.1.24",
        }
    }

    /// True when `value` can be read as this syntax.
    pub fn accepts(&self, value: &str) -> bool {
        match self {
            Syntax::DirectoryString | Syntax::OctetString => true,
            Syntax::Ia5String => value.is_ascii(),
            Syntax::Integer => {
                let digits = value.strip_prefix('-').unwrap_or(value);
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
            }
            Syntax::Boolean => {
                value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false")
            }
            Syntax::DistinguishedName => crate::dn::is_valid(value),
            // A descriptor is a legal value wherever an OID is: `objectClass: top`
            // is a name, not a dotted number (RFC 4512 §1.4).
            Syntax::Oid => is_descriptor(value) || is_numeric_oid(value),
            // `YYYYmmddHHMMSS[.fraction]Z`; the server writes the fraction, so the
            // validator has to accept the form it produces (RFC 4517 §3.3.13).
            Syntax::GeneralizedTime => {
                let body = value.strip_suffix('Z').unwrap_or(value);
                let (main, fraction) = match body.split_once('.') {
                    Some((main, fraction)) => (main, Some(fraction)),
                    None => (body, None),
                };
                main.len() == 14
                    && main.bytes().all(|byte| byte.is_ascii_digit())
                    && fraction.is_none_or(|fraction| {
                        !fraction.is_empty()
                            && fraction.len() <= 6
                            && fraction.bytes().all(|byte| byte.is_ascii_digit())
                    })
            }
        }
    }
}

fn is_descriptor(value: &str) -> bool {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    characters.all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn is_numeric_oid(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// One `attributetype` definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeType {
    pub oid: String,
    /// Every name, the first one being the primary.
    pub names: Vec<String>,
    pub sup: Option<String>,
    pub equality: Option<String>,
    pub ordering: Option<String>,
    pub substr: Option<String>,
    pub syntax: Option<Syntax>,
    /// Raw syntax OID as written, kept for publication even when unknown.
    pub syntax_oid: Option<String>,
    pub single_value: bool,
    pub operational: bool,
    pub no_user_modification: bool,
}

impl AttributeType {
    /// Primary name when there is one, otherwise the OID.
    pub fn primary_name(&self) -> &str {
        self.names.first().map(String::as_str).unwrap_or(&self.oid)
    }

    /// The definition in RFC 4512 syntax, as `attributeTypes` publishes it.
    ///
    /// Written back from the parsed form rather than stored verbatim: a client reading
    /// this gets exactly what the server enforces, which is the point of publishing it.
    /// The order of the keywords follows the ABNF, so the output can be re-parsed by
    /// this server and by OpenLDAP.
    pub fn definition(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];

        if !self.names.is_empty() {
            if self.names.len() == 1 {
                parts.push(format!("NAME '{}'", self.names[0]));
            } else {
                let names: Vec<String> =
                    self.names.iter().map(|name| format!("'{name}'")).collect();
                parts.push(format!("NAME ( {} )", names.join(" ")));
            }
        }
        if let Some(sup) = &self.sup {
            parts.push(format!("SUP {sup}"));
        }
        if let Some(equality) = &self.equality {
            parts.push(format!("EQUALITY {equality}"));
        }
        if let Some(ordering) = &self.ordering {
            parts.push(format!("ORDERING {ordering}"));
        }
        if let Some(substr) = &self.substr {
            parts.push(format!("SUBSTR {substr}"));
        }
        if let Some(oid) = &self.syntax_oid {
            parts.push(format!("SYNTAX {oid}"));
        }
        if self.single_value {
            parts.push("SINGLE-VALUE".to_string());
        }
        if self.operational {
            // `USAGE` is how a definition says "operational"; the specific usage is not
            // kept, and `directoryOperation` is what every one of ours is.
            parts.push("USAGE directoryOperation".to_string());
        }
        if self.no_user_modification {
            parts.push("NO-USER-MODIFICATION".to_string());
        }
        parts.push(")".to_string());

        parts.join(" ")
    }
}

/// Kind of an object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassKind {
    Abstract,
    Structural,
    Auxiliary,
}

/// One `objectclass` definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectClass {
    pub oid: String,
    pub names: Vec<String>,
    pub sup: Vec<String>,
    pub kind: ClassKind,
    pub must: Vec<String>,
    pub may: Vec<String>,
}

impl ObjectClass {
    pub fn primary_name(&self) -> &str {
        self.names.first().map(String::as_str).unwrap_or(&self.oid)
    }

    /// The definition in RFC 4512 syntax, as `objectClasses` publishes it.
    pub fn definition(&self) -> String {
        let mut parts = vec![format!("( {}", self.oid)];

        if !self.names.is_empty() {
            if self.names.len() == 1 {
                parts.push(format!("NAME '{}'", self.names[0]));
            } else {
                let names: Vec<String> =
                    self.names.iter().map(|name| format!("'{name}'")).collect();
                parts.push(format!("NAME ( {} )", names.join(" ")));
            }
        }
        if !self.sup.is_empty() {
            if self.sup.len() == 1 {
                parts.push(format!("SUP {}", self.sup[0]));
            } else {
                parts.push(format!("SUP ( {} )", self.sup.join(" $ ")));
            }
        }
        parts.push(
            match self.kind {
                ClassKind::Abstract => "ABSTRACT",
                ClassKind::Structural => "STRUCTURAL",
                ClassKind::Auxiliary => "AUXILIARY",
            }
            .to_string(),
        );

        if !self.must.is_empty() {
            if self.must.len() == 1 {
                parts.push(format!("MUST {}", self.must[0]));
            } else {
                parts.push(format!("MUST ( {} )", self.must.join(" $ ")));
            }
        }
        if !self.may.is_empty() {
            if self.may.len() == 1 {
                parts.push(format!("MAY {}", self.may[0]));
            } else {
                parts.push(format!("MAY ( {} )", self.may.join(" $ ")));
            }
        }
        parts.push(")".to_string());

        parts.join(" ")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("definition is not a parenthesised list: {0}")]
    NotASequence(String),
    #[error("unknown keyword '{keyword}' in {kind} definition")]
    UnknownKeyword { keyword: String, kind: &'static str },
    #[error("keyword '{keyword}' needs a value in {kind} definition")]
    MissingValue {
        keyword: &'static str,
        kind: &'static str,
    },
    #[error("{kind} definition without an object identifier")]
    MissingOid { kind: &'static str },
    #[error("unknown object class kind '{0}'")]
    UnknownClassKind(String),
    #[error("unknown syntax OID '{0}'")]
    UnknownSyntax(String),
    #[error("name '{name}' is defined twice")]
    DuplicateName { name: String },
    #[error("attribute type '{0}' is referenced before it is defined")]
    UnknownSuperior(String),
    #[error("object class '{0}' has no 'sup' chain ending at 'top'")]
    BrokenClassChain(String),
    #[error(
        "the definition starting on line {line} is never closed: its parentheses are still open \
         at the end of the file ('{text}')"
    )]
    Unterminated { line: usize, text: String },
}

/// Parsed schema: attribute types and object classes, resolved by name or OID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schema {
    attributes: BTreeMap<String, AttributeType>,
    classes: BTreeMap<String, ObjectClass>,
}

impl Schema {
    /// The minimum a directory needs to hold people, groups and OUs.
    pub fn core() -> Self {
        let mut schema = Self::default();
        schema
            .extend(CORE_DEFINITIONS)
            .expect("the built-in schema is valid");
        schema
    }

    /// Adds definitions, resolving names to OIDs.
    pub fn extend(&mut self, definitions: &str) -> Result<(), SchemaError> {
        for definition in split_definitions(definitions)? {
            let tokens = tokenize(&definition)?;
            match tokens.first().map(String::as_str) {
                Some("attributetype") | Some("attributeType") => {
                    let parsed = parse_attribute_type(&tokens)?;
                    self.insert_attribute(parsed)?;
                }
                Some("objectclass") | Some("objectClass") => {
                    let parsed = parse_object_class(&tokens)?;
                    self.insert_class(parsed)?;
                }
                Some(other) => {
                    return Err(SchemaError::UnknownKeyword {
                        keyword: other.to_string(),
                        kind: "definition",
                    });
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Builds the schema a server runs with: the built-in core, then files, then what the
    /// protocol added.
    ///
    /// One builder for both callers. Startup and a schema reload have to agree on the order and
    /// on what a failure means, and two copies of this loop is how they stop agreeing: the
    /// reload would eventually miss a source that startup had learned about, and the difference
    /// would show up as a definition that works until the server restarts.
    ///
    /// The order is a precedence: a later source may only add names still free, because a
    /// duplicate is refused rather than replaced. Inline definitions come last, so a definition
    /// added through `cn=schema,cn=config` is not shadowed by a file; a clash is reported either
    /// way and never resolved silently in favour of one source.
    pub fn from_sources(
        files: &[std::path::PathBuf],
        definitions: &[String],
    ) -> Result<Self, SchemaSource> {
        let mut schema = Self::core();

        for path in files {
            let text = std::fs::read_to_string(path).map_err(|source| SchemaSource::Read {
                path: path.display().to_string(),
                source,
            })?;

            schema.extend(&text).map_err(|source| SchemaSource::Parse {
                path: path.display().to_string(),
                source,
            })?;
        }

        for (position, definition) in definitions.iter().enumerate() {
            // Numbered from one: whoever added it counted the values they sent starting at one.
            schema
                .extend(definition)
                .map_err(|source| SchemaSource::Definition {
                    position: position + 1,
                    source,
                })?;
        }

        Ok(schema)
    }

    fn insert_attribute(&mut self, attribute: AttributeType) -> Result<(), SchemaError> {
        let keys = names_and_oid(&attribute.names, &attribute.oid);
        for key in &keys {
            if self.attributes.contains_key(key) {
                return Err(SchemaError::DuplicateName { name: key.clone() });
            }
        }
        for key in keys {
            self.attributes.insert(key, attribute.clone());
        }
        Ok(())
    }

    fn insert_class(&mut self, class: ObjectClass) -> Result<(), SchemaError> {
        let keys = names_and_oid(&class.names, &class.oid);
        for key in &keys {
            if self.classes.contains_key(key) {
                return Err(SchemaError::DuplicateName { name: key.clone() });
            }
        }
        for key in keys {
            self.classes.insert(key, class.clone());
        }
        Ok(())
    }

    /// Every attribute type, once, in a stable order.
    ///
    /// The map holds one entry per name and per OID, so the same definition appears
    /// several times; publishing it several times would confuse any client that counts.
    pub fn attribute_types(&self) -> Vec<&AttributeType> {
        let mut seen = BTreeSet::new();
        let mut types: Vec<&AttributeType> = Vec::new();

        for attribute in self.attributes.values() {
            if seen.insert(attribute.oid.clone()) {
                types.push(attribute);
            }
        }
        types.sort_by(|left, right| left.oid.cmp(&right.oid));
        types
    }

    /// Every object class, once, in a stable order.
    pub fn object_classes(&self) -> Vec<&ObjectClass> {
        let mut seen = BTreeSet::new();
        let mut classes: Vec<&ObjectClass> = Vec::new();

        for class in self.classes.values() {
            if seen.insert(class.oid.clone()) {
                classes.push(class);
            }
        }
        classes.sort_by(|left, right| left.oid.cmp(&right.oid));
        classes
    }

    /// How many distinct attribute types the schema holds, counted by OID.
    ///
    /// By OID rather than by name: an alias is the same type, and a schema that reports its
    /// size including aliases would look like it grew when a name was added.
    pub fn attribute_count(&self) -> usize {
        self.attribute_types().len()
    }

    /// How many distinct object classes the schema holds, counted by OID.
    pub fn class_count(&self) -> usize {
        self.object_classes().len()
    }

    pub fn attribute(&self, name: &str) -> Option<&AttributeType> {
        self.attributes.get(&name.to_lowercase())
    }

    pub fn class(&self, name: &str) -> Option<&ObjectClass> {
        self.classes.get(&name.to_lowercase())
    }

    /// Attribute type with its `sup` chain applied: syntax comes from the nearest
    /// ancestor that defines one, and `SINGLE-VALUE` is inherited.
    pub fn resolved(&self, name: &str) -> Option<AttributeType> {
        let mut current = self.attribute(name)?.clone();
        let mut seen = BTreeSet::new();
        let mut superior = current.sup.clone();

        while let Some(name) = superior {
            if !seen.insert(name.clone()) {
                break;
            }
            let Some(parent) = self.attribute(&name) else {
                break;
            };
            if current.syntax.is_none() {
                current.syntax = parent.syntax;
                current.syntax_oid = parent.syntax_oid.clone();
            }
            if current.equality.is_none() {
                current.equality = parent.equality.clone();
            }
            if current.ordering.is_none() {
                current.ordering = parent.ordering.clone();
            }
            if current.substr.is_none() {
                current.substr = parent.substr.clone();
            }
            current.single_value |= parent.single_value;
            current.operational |= parent.operational;
            superior = parent.sup.clone();
        }

        Some(current)
    }

    /// Attribute names an object class allows, following the `SUP` chain.
    pub fn allowed_attributes(
        &self,
        class_name: &str,
    ) -> Option<(BTreeSet<String>, BTreeSet<String>)> {
        let mut must = BTreeSet::new();
        let mut may = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut pending = vec![class_name.to_lowercase()];

        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let class = self.class(&name)?;
            for attribute in &class.must {
                must.insert(attribute.to_lowercase());
            }
            for attribute in &class.may {
                may.insert(attribute.to_lowercase());
            }
            pending.extend(class.sup.iter().map(|sup| sup.to_lowercase()));
        }

        Some((must, may))
    }

    /// True when every class in `classes` is an ancestor or descendant of the others,
    /// i.e. they form one chain rather than two branches.
    fn is_chain(&self, classes: &[String]) -> bool {
        if classes.len() <= 1 {
            return true;
        }
        for (index, left) in classes.iter().enumerate() {
            for right in &classes[index + 1..] {
                if !self.is_ancestor(left, right) && !self.is_ancestor(right, left) {
                    return false;
                }
            }
        }
        true
    }

    /// True when `ancestor` appears in the `SUP` chain of `class`.
    fn is_ancestor(&self, ancestor: &str, class: &str) -> bool {
        let mut seen = BTreeSet::new();
        let mut pending: Vec<String> = vec![class.to_lowercase()];
        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(definition) = self.class(&name) else {
                continue;
            };
            for superior in &definition.sup {
                let superior = superior.to_lowercase();
                if superior == ancestor.to_lowercase() {
                    return true;
                }
                pending.push(superior);
            }
        }
        false
    }

    /// Checks one entry against the schema.
    pub fn check(&self, entry: &Entry) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();
        let mut required: BTreeSet<String> = BTreeSet::new();
        let mut permitted: BTreeSet<String> = BTreeSet::new();
        let mut structural: Vec<String> = Vec::new();

        let mut classes = entry.object_classes().to_vec();
        if classes.is_empty() {
            violations.push(Violation {
                code: ViolationCode::ObjectClassViolation,
                detail: "entry has no objectClass".to_string(),
            });
        }
        classes.sort();
        classes.dedup();

        for class_name in &classes {
            let Some(class) = self.class(class_name) else {
                violations.push(Violation {
                    code: ViolationCode::ObjectClassViolation,
                    detail: format!("unknown object class '{class_name}'"),
                });
                continue;
            };
            if class.kind == ClassKind::Structural {
                structural.push(class_name.to_lowercase());
            }
            // Listing an abstract class such as `top` is not an error, it is the
            // normal shape of every entry; what a client cannot do is build an entry
            // out of abstract classes alone, which the structural count catches.
            match self.allowed_attributes(class_name) {
                Some((must, may)) => {
                    required.extend(must);
                    permitted.extend(may);
                }
                None => violations.push(Violation {
                    code: ViolationCode::ObjectClassViolation,
                    detail: format!("object class '{class_name}' is not fully defined"),
                }),
            }
        }

        // Several structural classes are normal — `person`, `organizationalPerson` and
        // `inetOrgPerson` are the standard way to write one entry — as long as they
        // form a single inheritance chain. Two unrelated structural classes are not.
        if !self.is_chain(&structural) {
            violations.push(Violation {
                code: ViolationCode::ObjectClassViolation,
                detail: format!(
                    "structural classes {structural:?} do not form one inheritance chain"
                ),
            });
        }

        // The naming attribute lives in the DN, not in the attribute list: this
        // server builds `dc=example,dc=com` and `ou=users,…` without repeating the
        // value as an attribute. It is therefore both allowed and present.
        let rdn_attribute = entry
            .dn()
            .split(',')
            .next()
            .and_then(|rdn| rdn.split_once('='))
            .map(|(attribute, _)| attribute.to_lowercase());
        if let Some(attribute) = &rdn_attribute {
            permitted.insert(attribute.clone());
        }

        for name in &required {
            if rdn_attribute.as_deref() == Some(name.as_str()) {
                continue;
            }
            if entry.attributes().get(name).is_none() {
                violations.push(Violation {
                    code: ViolationCode::ObjectClassViolation,
                    detail: format!("required attribute '{name}' is missing"),
                });
            }
        }

        for attribute in entry.attributes().values() {
            let name = attribute.name.to_lowercase();

            // Operational attributes (`entryUUID`, timestamps, counters) are maintained
            // by the server and are not governed by object classes; RFC 4512 leaves
            // them out of the content rules.
            // Server-internal attributes are outside the directory altogether.
            if attribute.flags.internal {
                continue;
            }
            let is_operational = attribute.flags.operational
                || self
                    .resolved(&name)
                    .map(|definition| definition.operational)
                    .unwrap_or(false);
            if is_operational {
                continue;
            }

            if !permitted.contains(&name) && !required.contains(&name) {
                violations.push(Violation {
                    code: ViolationCode::ObjectClassViolation,
                    detail: format!("attribute '{name}' is not allowed by any object class"),
                });
                continue;
            }

            let Some(kind) = self.resolved(&name) else {
                violations.push(Violation {
                    code: ViolationCode::UndefinedAttributeType,
                    detail: format!("attribute type '{name}' is not defined by the schema"),
                });
                continue;
            };

            if kind.single_value && attribute.values.len() > 1 {
                violations.push(Violation {
                    code: ViolationCode::ConstraintViolation,
                    detail: format!(
                        "attribute '{name}' is single-valued but has {} values",
                        attribute.values.len()
                    ),
                });
            }

            if let Some(syntax) = kind.syntax {
                for value in attribute.values.iter() {
                    if !syntax.accepts(value) {
                        violations.push(Violation {
                            code: ViolationCode::InvalidAttributeSyntax,
                            detail: format!("value of '{name}' does not match {}", syntax.oid()),
                        });
                    }
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Result code an LDAP client expects for a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    ObjectClassViolation,
    ConstraintViolation,
    UndefinedAttributeType,
    InvalidAttributeSyntax,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: ViolationCode,
    pub detail: String,
}

/// How strictly the server enforces the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Violations refuse the write.
    #[default]
    Strict,
    /// Violations are reported, the write proceeds.
    Warn,
    /// No checking at all; the schema is still published.
    Off,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "strict" => Ok(Mode::Strict),
            "warn" => Ok(Mode::Warn),
            "off" => Ok(Mode::Off),
            other => Err(format!(
                "unknown schema mode '{other}', expected strict, warn or off"
            )),
        }
    }
}

fn names_and_oid(names: &[String], oid: &str) -> Vec<String> {
    let mut keys: Vec<String> = names.iter().map(|name| name.to_lowercase()).collect();
    keys.push(oid.to_string());
    keys
}

/// Splits a schema text into definitions: every top-level parenthesised block.
/// Splits a schema text into its definitions, joining continuation lines.
///
/// A definition continues until its parentheses balance. One that never balances is an error
/// and not a line to drop: a file with a missing `)` is the shape a half-saved edit takes, and
/// silently ignoring it means the schema in force is not the one somebody wrote - the
/// definition simply is not there, and nothing says so until a write is refused for an
/// attribute the operator is sure they defined.
fn split_definitions(text: &str) -> Result<Vec<String>, SchemaError> {
    let mut definitions = Vec::new();
    let mut current: Option<(usize, String)> = None;

    for (index, line) in text.lines().enumerate() {
        let line = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match current.as_mut() {
            None => {
                if trimmed.contains('(') {
                    current = Some((index + 1, trimmed.to_string()));
                }
            }
            Some((_, buffer)) => {
                buffer.push(' ');
                buffer.push_str(trimmed);
            }
        }

        if let Some((_, buffer)) = current.as_ref().filter(|(_, buffer)| balanced(buffer)) {
            definitions.push(buffer.clone());
            current = None;
        }
    }

    if let Some((line, text)) = current {
        return Err(SchemaError::Unterminated { line, text });
    }

    Ok(definitions)
}

fn balanced(text: &str) -> bool {
    let mut depth = 0i32;
    let mut in_quote = false;
    for character in text.chars() {
        match character {
            '\'' => in_quote = !in_quote,
            '(' if !in_quote => depth += 1,
            ')' if !in_quote => depth -= 1,
            _ => {}
        }
    }
    depth == 0 && !in_quote
}

/// Tokens: parentheses, the `$` separator, quoted strings and bare words.
fn tokenize(text: &str) -> Result<Vec<String>, SchemaError> {
    let mut tokens = Vec::new();
    let mut characters = text.chars().peekable();

    while let Some(character) = characters.next() {
        match character {
            c if c.is_whitespace() => {}
            '(' | ')' | '$' => tokens.push(character.to_string()),
            '\'' => {
                let mut value = String::new();
                loop {
                    match characters.next() {
                        Some('\'') => break,
                        Some(other) => value.push(other),
                        None => {
                            return Err(SchemaError::NotASequence(text.to_string()));
                        }
                    }
                }
                tokens.push(value);
            }
            other => {
                let mut word = String::from(other);
                while let Some(next) = characters.peek() {
                    if next.is_whitespace() || matches!(next, '(' | ')' | '$' | '\'') {
                        break;
                    }
                    word.push(characters.next().expect("peeked"));
                }
                tokens.push(word);
            }
        }
    }

    Ok(tokens)
}

fn parse_attribute_type(tokens: &[String]) -> Result<AttributeType, SchemaError> {
    let mut cursor = Cursor::new(tokens, 1);
    cursor.expect_open()?;

    let oid = cursor.word().ok_or(SchemaError::MissingOid {
        kind: "attributetype",
    })?;
    if !is_numeric_oid(&oid) && !is_descriptor(&oid)
        || ATTRIBUTE_KEYWORDS.contains(&oid.to_ascii_uppercase().as_str())
    {
        return Err(SchemaError::MissingOid {
            kind: "attributetype",
        });
    }

    let mut attribute = AttributeType {
        oid,
        names: Vec::new(),
        sup: None,
        equality: None,
        ordering: None,
        substr: None,
        syntax: None,
        syntax_oid: None,
        single_value: false,
        operational: false,
        no_user_modification: false,
    };

    while let Some(keyword) = cursor.word() {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => attribute.names = cursor.names()?,
            "DESC" => {
                cursor.names()?;
            }
            "OBSOLETE" => {}
            "SUP" => attribute.sup = Some(cursor.single_or_first()?),
            "EQUALITY" => attribute.equality = Some(cursor.single_or_first()?),
            "ORDERING" => attribute.ordering = Some(cursor.single_or_first()?),
            "SUBSTR" => attribute.substr = Some(cursor.single_or_first()?),
            "SYNTAX" => {
                let raw = cursor.single_or_first()?;
                let oid = raw.split('{').next().unwrap_or(&raw).to_string();
                attribute.syntax = Syntax::from_oid(&oid);
                attribute.syntax_oid = Some(oid);
            }
            "SINGLE-VALUE" => attribute.single_value = true,
            "COLLECTIVE" => {}
            "NO-USER-MODIFICATION" => attribute.no_user_modification = true,
            "USAGE" => {
                let usage = cursor.single_or_first()?;
                if !usage.eq_ignore_ascii_case("userApplications") {
                    attribute.operational = true;
                }
            }
            other => {
                return Err(SchemaError::UnknownKeyword {
                    keyword: other.to_string(),
                    kind: "attributetype",
                });
            }
        }
    }

    Ok(attribute)
}

fn parse_object_class(tokens: &[String]) -> Result<ObjectClass, SchemaError> {
    let mut cursor = Cursor::new(tokens, 1);
    cursor.expect_open()?;

    let oid = cursor.word().ok_or(SchemaError::MissingOid {
        kind: "objectclass",
    })?;
    if CLASS_KEYWORDS.contains(&oid.to_ascii_uppercase().as_str()) {
        return Err(SchemaError::MissingOid {
            kind: "objectclass",
        });
    }

    let mut class = ObjectClass {
        oid,
        names: Vec::new(),
        sup: Vec::new(),
        kind: ClassKind::Structural,
        must: Vec::new(),
        may: Vec::new(),
    };

    while let Some(keyword) = cursor.word() {
        match keyword.to_ascii_uppercase().as_str() {
            "NAME" => class.names = cursor.names()?,
            "DESC" => {
                cursor.names()?;
            }
            "OBSOLETE" => {}
            "SUP" => class.sup = cursor.list()?,
            "ABSTRACT" => class.kind = ClassKind::Abstract,
            "STRUCTURAL" => class.kind = ClassKind::Structural,
            "AUXILIARY" => class.kind = ClassKind::Auxiliary,
            "MUST" => class.must = cursor.list()?,
            "MAY" => class.may = cursor.list()?,
            other => return Err(SchemaError::UnknownClassKind(other.to_string())),
        }
    }

    Ok(class)
}

/// Keywords that may appear inside a definition; seeing one where the OID belongs
/// means the OID was forgotten, and saying so is more useful than parsing `NAME` as
/// an identifier.
const ATTRIBUTE_KEYWORDS: [&str; 11] = [
    "NAME",
    "DESC",
    "OBSOLETE",
    "SUP",
    "EQUALITY",
    "ORDERING",
    "SUBSTR",
    "SYNTAX",
    "SINGLE-VALUE",
    "COLLECTIVE",
    "USAGE",
];

const CLASS_KEYWORDS: [&str; 9] = [
    "NAME",
    "DESC",
    "OBSOLETE",
    "SUP",
    "ABSTRACT",
    "STRUCTURAL",
    "AUXILIARY",
    "MUST",
    "MAY",
];

/// Small token cursor, so the parsers above read like the grammar they implement.
struct Cursor<'a> {
    tokens: &'a [String],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [String], position: usize) -> Self {
        Self { tokens, position }
    }

    fn expect_open(&mut self) -> Result<(), SchemaError> {
        if self.tokens.get(self.position).map(String::as_str) == Some("(") {
            self.position += 1;
            Ok(())
        } else {
            Err(SchemaError::NotASequence(self.tokens.join(" ")))
        }
    }

    /// Next word that is not a delimiter, skipping a closing paren.
    fn word(&mut self) -> Option<String> {
        while let Some(token) = self.tokens.get(self.position) {
            self.position += 1;
            if token == ")" {
                return None;
            }
            if token != "(" && token != "$" {
                return Some(token.clone());
            }
        }
        None
    }

    /// `'name'` or `( 'name' 'alias' … )`.
    fn names(&mut self) -> Result<Vec<String>, SchemaError> {
        if self.tokens.get(self.position).map(String::as_str) != Some("(") {
            return Ok(vec![self.word().ok_or(SchemaError::MissingValue {
                keyword: "NAME",
                kind: "definition",
            })?]);
        }
        self.position += 1;
        let mut names = Vec::new();
        while let Some(token) = self.tokens.get(self.position) {
            self.position += 1;
            match token.as_str() {
                ")" => break,
                "$" => {}
                other => names.push(other.to_string()),
            }
        }
        Ok(names)
    }

    /// A bare value, or the first element of a parenthesised list.
    fn single_or_first(&mut self) -> Result<String, SchemaError> {
        let mut values = self.list()?;
        if values.is_empty() {
            return Err(SchemaError::MissingValue {
                keyword: "SUP",
                kind: "definition",
            });
        }
        Ok(values.remove(0))
    }

    /// `value` or `( value $ value … )`.
    fn list(&mut self) -> Result<Vec<String>, SchemaError> {
        if self.tokens.get(self.position).map(String::as_str) != Some("(") {
            return self
                .word()
                .map(|value| vec![value])
                .ok_or(SchemaError::MissingValue {
                    keyword: "list",
                    kind: "definition",
                });
        }
        self.position += 1;
        let mut values = Vec::new();
        while let Some(token) = self.tokens.get(self.position) {
            self.position += 1;
            match token.as_str() {
                ")" => break,
                "$" => {}
                other => values.push(other.to_string()),
            }
        }
        Ok(values)
    }
}

/// The built-in subset: enough for the directory this server serves, written in the
/// same syntax an operator would use, so it doubles as an example.
const CORE_DEFINITIONS: &str = "\
attributetype ( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )
attributetype ( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )
attributetype ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.42 NAME ( 'givenName' 'gn' ) SUP name )
attributetype ( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SUP name )
attributetype ( 0.9.2342.19200300.100.1.25 NAME ( 'dc' 'domainComponent' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetype ( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetype ( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 2.5.4.12 NAME 'title' SUP name )
attributetype ( 2.5.4.23 NAME ( 'facsimileTelephoneNumber' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
attributetype ( 1.3.6.1.4.1.42.2.27.4.1.6 NAME 'pager' SUP name )
attributetype ( 1.3.6.1.1.1.1.7 NAME 'shadowLastChange' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 2.5.4.21 NAME 'registeredAddress' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.20 NAME 'telephoneNumber' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.34 NAME 'seeAlso' SUP distinguishedName )
attributetype ( 2.5.4.49 NAME 'distinguishedName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributetype ( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
attributetype ( 2.5.4.36 NAME 'userCertificate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
attributetype ( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.1.1.1.2 NAME 'gecos' SUP name )
attributetype ( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetype ( 1.3.6.1.1.1.1.4 NAME 'loginShell' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributetype ( 2.5.4.10 NAME ( 'o' 'organizationName' ) SUP name )
attributetype ( 2.16.840.1.113730.3.1.3 NAME 'employeeNumber' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 0.9.2342.19200300.100.1.2 NAME 'textEncodedORAddress' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 0.9.2342.19200300.100.1.4 NAME 'info' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 0.9.2342.19200300.100.1.5 NAME 'drink' SUP name )
attributetype ( 0.9.2342.19200300.100.1.6 NAME 'roomNumber' SUP name )
attributetype ( 1.3.6.1.1.1.1.6 NAME 'room' SUP name )
attributetype ( 1.3.6.1.1.1.1.9 NAME 'host' SUP name )
attributetype ( 1.3.6.1.1.1.1.5 NAME 'memberUid' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributetype ( 2.5.4.31 NAME 'member' SUP distinguishedName )
# gorestldap fills memberOf with group names, not DNs: the port keeps that
# contract, so the syntax here is text rather than distinguishedName.
attributetype ( 1.2.840.113556.1.2.102 NAME 'memberOf' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 2.5.4.45 NAME ( 'x500UniqueIdentifier' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.1.16.4 NAME 'entryUUID' EQUALITY uuidMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
# entryCSN and entryUUID are operational in OpenLDAP as well; without USAGE the
# published definition would disagree with what the server does to the attribute.
attributetype ( 1.3.6.1.1.16.1 NAME 'entryCSN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.2 NAME 'modifyTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.3 NAME 'creatorsName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 2.5.18.4 NAME 'modifiersName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributetype ( 1.3.6.1.1.1.1.12 NAME 'hasSubordinates' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
objectclass ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )
objectclass ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )
objectclass ( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ givenName $ employeeNumber ) )
objectclass ( 2.5.6.9 NAME 'organizationalRole' SUP top STRUCTURAL MUST cn MAY ( description $ telephoneNumber ) )
objectclass ( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ displayName $ homeDirectory $ loginShell $ roomNumber $ o $ info $ drink $ memberOf $ title $ facsimileTelephoneNumber $ jpegPhoto $ pager $ description ) )
objectclass ( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )
objectclass ( 1.3.6.1.1.1.2.1 NAME 'shadowAccount' SUP top AUXILIARY MUST uid MAY ( userPassword $ shadowLastChange $ description ) )
objectclass ( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top STRUCTURAL MUST ( cn $ gidNumber ) MAY ( userPassword $ memberUid $ description ) )
objectclass ( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY description )
objectclass ( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY ( o $ description ) )
objectclass ( 2.5.6.9.1 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( cn $ member ) MAY ( description ) )
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes};

    fn entry(dn: &str, attributes: Attributes) -> Entry {
        Entry::new(dn, attributes)
    }

    fn person(cn: &str) -> Attributes {
        Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", cn))
            .push(Attribute::single("sn", "Doe"))
    }

    #[test]
    fn parses_a_simple_attribute_type() {
        let mut schema = Schema::default();
        schema
            .extend("attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )")
            .expect("parse");

        let attribute = schema.attribute("cn").expect("cn");
        assert_eq!(attribute.oid, "2.5.4.3");
        assert_eq!(attribute.names, vec!["cn", "commonName"]);
        assert_eq!(attribute.sup.as_deref(), Some("name"));
    }

    #[test]
    fn multi_line_definitions_and_comments_are_read() {
        let mut schema = Schema::default();
        schema
            .extend(
                "\
# a comment
attributetype ( 2.5.4.3 NAME ( 'cn' 'commonName' )
    SUP name )
attributetype ( 2.5.4.41 NAME 'name'
    EQUALITY caseIgnoreMatch
    SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
",
            )
            .expect("parse");

        assert_eq!(
            schema.attribute("cn").and_then(|a| a.sup.as_deref()),
            Some("name")
        );
        assert_eq!(
            schema.attribute("name").and_then(|a| a.syntax),
            Some(Syntax::DirectoryString)
        );
    }

    #[test]
    fn parses_an_object_class_with_lists() {
        let mut schema = Schema::default();
        schema
            .extend(
                "objectclass ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL \
                 MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
            )
            .expect("parse");

        let class = schema.class("person").expect("person");
        assert_eq!(class.kind, ClassKind::Structural);
        assert_eq!(class.sup, vec!["top"]);
        assert_eq!(class.must, vec!["sn", "cn"]);
        assert_eq!(class.may, vec!["userPassword", "telephoneNumber"]);
    }

    #[test]
    fn single_quoted_name_without_parentheses_is_accepted() {
        let mut schema = Schema::default();
        schema
            .extend("objectclass ( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )")
            .expect("parse");

        assert_eq!(
            schema
                .class("organizationalUnit")
                .map(|class| class.must.clone()),
            Some(vec!["ou".to_string()])
        );
    }

    #[test]
    fn syntax_with_length_suffix_is_understood() {
        let mut schema = Schema::default();
        schema
            .extend("attributetype ( 1.2.3.4 NAME 'x' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27{10} )")
            .expect("parse");

        let attribute = schema.attribute("x").expect("x");
        assert_eq!(attribute.syntax, Some(Syntax::Integer));
        assert_eq!(
            attribute.syntax_oid.as_deref(),
            Some("1.3.6.1.4.1.1466.115.121.1.27")
        );
    }

    #[test]
    fn an_unknown_keyword_is_rejected() {
        let mut schema = Schema::default();
        let error = schema
            .extend("attributetype ( 1.2.3.4 NAME 'x' MSU cn )")
            .expect_err("must reject");

        assert_eq!(
            error,
            SchemaError::UnknownKeyword {
                keyword: "MSU".to_string(),
                kind: "attributetype"
            }
        );
    }

    #[test]
    fn a_definition_without_an_oid_is_rejected() {
        let mut schema = Schema::default();
        let error = schema
            .extend("attributetype ( NAME 'x' )")
            .expect_err("must reject");

        assert!(matches!(error, SchemaError::MissingOid { .. }), "{error:?}");
    }

    #[test]
    fn a_duplicate_name_is_rejected() {
        let mut schema = Schema::core();
        let error = schema
            .extend("attributetype ( 1.2.3.4 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )")
            .expect_err("must reject");

        assert_eq!(
            error,
            SchemaError::DuplicateName {
                name: "cn".to_string()
            }
        );
    }

    #[test]
    fn superiors_are_followed_for_syntax_and_single_value() {
        let schema = Schema::core();

        let cn = schema.resolved("cn").expect("cn");
        assert_eq!(
            cn.syntax,
            Some(Syntax::DirectoryString),
            "cn inherits its syntax from name"
        );

        let uid_number = schema.resolved("uidNumber").expect("uidNumber");
        assert!(uid_number.single_value);
        assert_eq!(uid_number.syntax, Some(Syntax::Integer));
    }

    #[test]
    fn required_attributes_are_inherited_through_sup() {
        let schema = Schema::core();

        let (must, may) = schema
            .allowed_attributes("inetOrgPerson")
            .expect("allowed attributes");

        assert!(must.contains("cn"), "cn comes from person");
        assert!(must.contains("sn"), "sn comes from person");
        assert!(may.contains("mail"), "mail is inetOrgPerson's own");
        assert!(
            may.contains("telephonenumber"),
            "telephoneNumber comes from person"
        );
    }

    #[test]
    fn a_complete_entry_passes() {
        let schema = Schema::core();
        let entry = entry("cn=ann,ou=users,dc=example,dc=com", person("ann"));

        assert_eq!(schema.check(&entry), Ok(()));
    }

    #[test]
    fn a_missing_required_attribute_is_a_violation() {
        let schema = Schema::core();
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "person".to_string()],
            ))
            .push(Attribute::single("cn", "ann"));
        let entry = entry("cn=ann,ou=users,dc=example,dc=com", attributes);

        let violations = schema.check(&entry).expect_err("must fail");

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].code, ViolationCode::ObjectClassViolation);
        assert_eq!(violations[0].detail, "required attribute 'sn' is missing");
    }

    #[test]
    fn an_attribute_outside_the_object_classes_is_a_violation() {
        let schema = Schema::core();
        let attributes = person("ann").push(Attribute::single("drink", "tea"));
        let entry = entry("cn=ann,ou=users,dc=example,dc=com", attributes);

        let violations = schema.check(&entry).expect_err("must fail");

        assert_eq!(
            violations[0].detail,
            "attribute 'drink' is not allowed by any object class"
        );
    }

    #[test]
    fn a_single_valued_attribute_with_two_values_is_refused() {
        let schema = Schema::core();
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "posixAccount".to_string()],
            ))
            .push(Attribute::single("cn", "ann"))
            .push(Attribute::single("uid", "ann"))
            .push(Attribute::new(
                "uidNumber",
                vec!["1000".to_string(), "1001".to_string()],
            ))
            .push(Attribute::single("gidNumber", "100"))
            .push(Attribute::single("homeDirectory", "/home/ann"));
        let entry = entry("cn=ann,ou=users,dc=example,dc=com", attributes);

        let violations = schema.check(&entry).expect_err("must fail");

        assert!(
            violations.iter().any(|violation| {
                violation.code == ViolationCode::ConstraintViolation
                    && violation.detail.contains("single-valued")
            }),
            "unexpected: {violations:?}"
        );
    }

    #[test]
    fn a_value_of_the_wrong_syntax_is_refused() {
        let schema = Schema::core();
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "posixAccount".to_string()],
            ))
            .push(Attribute::single("cn", "ann"))
            .push(Attribute::single("uid", "ann"))
            .push(Attribute::single("uidNumber", "not-a-number"))
            .push(Attribute::single("gidNumber", "100"))
            .push(Attribute::single("homeDirectory", "/home/ann"));
        let entry = entry("cn=ann,ou=users,dc=example,dc=com", attributes);

        let violations = schema.check(&entry).expect_err("must fail");

        assert!(
            violations
                .iter()
                .any(|violation| violation.code == ViolationCode::InvalidAttributeSyntax),
            "unexpected: {violations:?}"
        );
    }

    #[test]
    fn an_undefined_attribute_type_is_named_as_such() {
        let mut schema = Schema::core();
        // A class that allows an attribute the schema does not define.
        schema
            .extend("objectclass ( 1.2.3.4.5 NAME 'widget' SUP top STRUCTURAL MUST cn MAY gadget )")
            .expect("parse");
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec!["top".to_string(), "widget".to_string()],
            ))
            .push(Attribute::single("cn", "w"))
            .push(Attribute::single("gadget", "x"));
        let entry = entry("cn=w,dc=example,dc=com", attributes);

        let violations = schema.check(&entry).expect_err("must fail");

        assert!(
            violations
                .iter()
                .any(|violation| violation.code == ViolationCode::UndefinedAttributeType),
            "unexpected: {violations:?}"
        );
    }

    #[test]
    fn two_structural_classes_are_refused() {
        let schema = Schema::core();
        let attributes = Attributes::new()
            .push(Attribute::new(
                "objectClass",
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "organizationalUnit".to_string(),
                ],
            ))
            .push(Attribute::single("cn", "ann"))
            .push(Attribute::single("sn", "Doe"))
            .push(Attribute::single("ou", "users"));
        let entry = entry("cn=ann,dc=example,dc=com", attributes);

        let violations = schema.check(&entry).expect_err("must fail");

        assert!(
            violations
                .iter()
                .any(|violation| violation.detail.contains("structural classes")),
            "unexpected: {violations:?}"
        );
    }

    #[test]
    fn the_naming_attribute_is_always_allowed() {
        let schema = Schema::core();
        // `dc` is required by the domain class; the entry names itself with it.
        let attributes = Attributes::new().push(Attribute::new(
            "objectClass",
            vec!["top".to_string(), "domain".to_string()],
        ));
        let entry = entry("dc=example,dc=com", attributes);

        assert_eq!(schema.check(&entry), Ok(()));
    }

    #[test]
    fn syntax_checkers_accept_and_reject_the_expected_values() {
        assert!(Syntax::Integer.accepts("42"));
        assert!(Syntax::Integer.accepts("-42"));
        assert!(!Syntax::Integer.accepts("4.2"));
        assert!(Syntax::Boolean.accepts("TRUE"));
        assert!(!Syntax::Boolean.accepts("yes"));
        assert!(Syntax::Ia5String.accepts("a@b.c"));
        assert!(!Syntax::Ia5String.accepts("почта@пример.рф"));
        assert!(Syntax::DistinguishedName.accepts("cn=a,dc=example,dc=com"));
        assert!(!Syntax::DistinguishedName.accepts("not a dn"));
        assert!(Syntax::GeneralizedTime.accepts("20261102120000Z"));
        assert!(
            Syntax::GeneralizedTime.accepts("20261102120000.123456Z"),
            "the server writes a fractional part"
        );
        assert!(!Syntax::GeneralizedTime.accepts("20261102120000.Z"));
        assert!(!Syntax::GeneralizedTime.accepts("20261102120000.1234567Z"));
        assert!(!Syntax::GeneralizedTime.accepts("2026-11-02"));
    }

    #[test]
    fn mode_is_parsed_from_configuration() {
        use std::str::FromStr as _;

        assert_eq!(Mode::from_str("strict"), Ok(Mode::Strict));
        assert_eq!(Mode::from_str("WARN"), Ok(Mode::Warn));
        assert_eq!(Mode::from_str(" off "), Ok(Mode::Off));
        assert_eq!(
            Mode::from_str("lenient"),
            Err("unknown schema mode 'lenient', expected strict, warn or off".to_string())
        );
    }

    #[test]
    fn the_built_in_schema_covers_the_entries_this_server_serves() {
        let schema = Schema::core();

        for class in [
            "top",
            "domain",
            "organizationalUnit",
            "person",
            "inetOrgPerson",
            "posixAccount",
            "posixGroup",
            "groupOfNames",
        ] {
            assert!(schema.class(class).is_some(), "{class} must be defined");
        }
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    const DRINK: &str = "attributeType ( 1.3.6.1.4.1.59999.2.1 NAME 'favouriteDrink' \
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

    #[test]
    fn definitions_follow_the_files_and_are_counted_from_one() {
        let schema = Schema::from_sources(&[], &[DRINK.to_string()]).expect("built");
        assert!(schema.attribute("favouritedrink").is_some());
    }

    #[test]
    fn a_broken_definition_is_reported_by_position() {
        // The number a client counts to, not a byte offset: the operator has to be able to point
        // at the value in the request that caused it.
        let err = Schema::from_sources(
            &[],
            &[
                DRINK.to_string(),
                "attributeType ( NAME 'noOid' )".to_string(),
            ],
        )
        .expect_err("the second definition is not usable");

        let text = err.to_string();
        assert!(text.contains("definition 2"), "{text}");
        assert!(text.contains("cn=schema,cn=config"), "{text}");
    }

    #[test]
    fn a_definition_that_collides_with_a_file_is_reported_rather_than_replacing_it() {
        // Order decides nothing about a duplicate: the file is already in, and `extend` refuses
        // the newcomer, so the clash is visible instead of one source silently winning.
        let schema = Schema::from_sources(&[], &[DRINK.to_string(), DRINK.to_string()]);
        assert!(
            schema.is_err(),
            "the same name twice is an error, not a replacement"
        );
    }

    #[test]
    fn an_unreadable_file_names_the_path() {
        let err = Schema::from_sources(&[std::path::PathBuf::from("/nonexistent/x.schema")], &[])
            .expect_err("the file is not there");

        let text = err.to_string();
        assert!(text.contains("/nonexistent/x.schema"), "{text}");
    }
}
