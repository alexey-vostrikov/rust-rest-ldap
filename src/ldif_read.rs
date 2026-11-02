//! The LDIF reader: RFC 2849, the format every directory tool speaks.
//!
//! The exporter in `ldif.rs` writes one shape - `dn` and then attributes - because that is
//! all a dump needs. Reading is the other half, and it has to accept what other tools write:
//! `slapcat` output, hand-edited files, `changetype: modify` blocks with their `-`
//! separators, base64 values, values pulled from files by URL, comments in the middle of a
//! record, and files that end without a blank line.
//!
//! Two rules decide the shape of this module:
//!
//! - **Unfold first, interpret second.** A continuation line is a transport detail: joining
//!   it after deciding what the line means would make a base64 value that was folded in the
//!   middle undecodable, and folding is exactly what a 76-octet limit forces.
//! - **Refuse rather than skip.** Every mistake here is a file somebody will import into a
//!   directory they care about. A line that is not an attribute, a value before its operator,
//!   a `changetype` that does not exist: each one is reported with its line number, because
//!   the alternative is an entry that is silently missing a value.

use crate::model::{Attribute, Attributes, Entry};
use crate::mutate::Op;
use thiserror::Error;

/// One record of an LDIF file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// An entry to add: `dn` followed by attributes.
    Entry(Content),
    /// A change to an existing entry: `dn`, `changetype`, and the change itself.
    Change(ChangeRecord),
}

/// An entry as a content record describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub entry: Entry,
}

/// The operations a change record may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// `changetype: add`, or a content record with a `changetype` line.
    Add,
    Modify,
    Delete,
    /// `changetype: modrdn`, and its older spelling `moddn`.
    ModDn,
}

/// One specification of a `changetype: modify` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modification {
    pub op: ModOp,
    pub attribute: String,
    /// Empty for a `delete` that removes the whole attribute.
    pub values: Vec<String>,
}

/// The operator of one modification, spelled as the file spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModOp {
    Add,
    Delete,
    Replace,
}

impl From<ModOp> for Op {
    fn from(op: ModOp) -> Self {
        match op {
            ModOp::Add => Op::Add,
            ModOp::Delete => Op::Delete,
            ModOp::Replace => Op::Replace,
        }
    }
}

/// A change record, whatever kind it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRecord {
    pub dn: String,
    pub change: Change,
    /// The specifications of a `modify`; empty for every other kind.
    pub modifications: Vec<Modification>,
    /// `newrdn` of a `modrdn`; `None` for every other kind.
    pub new_rdn: Option<String>,
    /// `deleteoldrdn` of a `modrdn`, in the file's own 0/1 spelling.
    pub delete_old_rdn: Option<bool>,
    /// `newsuperior` of a `modrdn`, when the entry also moves.
    pub new_superior: Option<String>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("line {line}: a line that is neither an attribute nor a record separator: '{text}'")]
    NotAnAttribute { line: usize, text: String },
    #[error("line {line}: the first line of a record must be 'dn:', but it is '{text}'")]
    NotADn { line: usize, text: String },
    #[error("line {line}: a continuation line (' {text}') has nothing to continue")]
    OrphanContinuation { line: usize, text: String },
    #[error("line {line}: '{name}' is not valid base64: {detail}")]
    Base64 {
        line: usize,
        name: String,
        detail: String,
    },
    #[error("line {line}: cannot read the value of '{name}' from '{url}': {detail}")]
    Url {
        line: usize,
        name: String,
        url: String,
        detail: String,
    },
    #[error(
        "line {line}: '{url}' is not a URL this reader fetches; only file:// is read, because \
         importing a directory must not depend on the network"
    )]
    UnsupportedUrl { line: usize, url: String },
    #[error("line {line}: unknown 'changetype: {value}'; expected add, modify, delete or modrdn")]
    UnknownChangeType { line: usize, value: String },
    #[error(
        "line {line}: unknown modification operator '{value}'; expected add, delete or replace"
    )]
    UnknownModOp { line: usize, value: String },
    #[error(
        "line {line}: '{name}' appears before any 'add:', 'delete:' or 'replace:', so it belongs \
         to no modification"
    )]
    ValueBeforeOperator { line: usize, name: String },
    #[error("line {line}: a 'changetype: modify' record has no modifications")]
    EmptyModify { line: usize },
    #[error("line {line}: a 'changetype: modrdn' record has no 'newrdn:'")]
    MissingNewRdn { line: usize },
    #[error("line {line}: 'deleteoldrdn' must be 0 or 1, not '{value}'")]
    BadDeleteOldRdn { line: usize, value: String },
    #[error("line {line}: this reader understands 'version: 1', not 'version: {value}'")]
    UnsupportedVersion { line: usize, value: String },
}

/// Parses a whole LDIF document.
pub fn parse(text: &str) -> Result<Vec<Record>, Error> {
    let physical = split_records(text);

    // RFC 2849 §3.1: a document may open with `version: 1` before the first record. Every
    // `slapcat` dump does, and refusing it would refuse the output of the tool this reader
    // exists to accept.
    let skip = match physical.first() {
        Some(first) if first.lines.len() == 1 => {
            let text = &first.lines[0].1;
            if text.starts_with("version:") {
                let value = text
                    .split_once(':')
                    .map(|(_, value)| value.trim())
                    .unwrap_or_default();

                if value != "1" {
                    return Err(Error::UnsupportedVersion {
                        line: first.lines[0].0,
                        value: value.to_string(),
                    });
                }
                1
            } else {
                0
            }
        }
        _ => 0,
    };

    let mut records = Vec::new();

    for record in physical.into_iter().skip(skip) {
        if let Some(record) = parse_record(&record)? {
            records.push(record);
        }
    }

    Ok(records)
}

/// One physical record: its lines, each with its line number for error messages.
struct Physical {
    /// Unfolded lines: continuations already joined.
    lines: Vec<(usize, String)>,
}

/// Splits the document into records, unfolding each.
///
/// Unfolding happens here rather than per line because a continuation is a property of the
/// transport, not of the content: `dn` and its fold, `::` and its fold, and a `-` separator
/// all arrive the same way, and a reader that unfolded only inside values would still break
/// on a folded `dn`.
fn split_records(text: &str) -> Vec<Physical> {
    let mut records = Vec::new();
    let mut current: Vec<(usize, String)> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        // CRLF files arrive from Windows and through mail; the CR is not content.
        let line = raw.strip_suffix('\r').unwrap_or(raw);

        if line.is_empty() {
            if !current.is_empty() {
                records.push(Physical {
                    lines: std::mem::take(&mut current),
                });
            }
            continue;
        }

        // A comment is dropped before anything else looks at the line: `slapcat` writes them
        // inside records, and an attribute called "#" is never what was meant.
        if line.starts_with('#') {
            continue;
        }

        match line.strip_prefix(' ') {
            // A continuation joins the previous line without its leading space. The rest of
            // the line, spaces included, is the value.
            Some(rest) => match current.last_mut() {
                Some((_, previous)) => previous.push_str(rest),
                None => current.push((number, String::new())),
            },
            None => current.push((number, line.to_string())),
        }
    }

    if !current.is_empty() {
        records.push(Physical { lines: current });
    }

    // An orphan continuation was stored as an empty line with no prefix; it is reported by
    // `parse_record` because only it knows what the record was supposed to be.
    records
}

/// One attribute line, as parsed.
struct Line {
    number: usize,
    name: String,
    /// `:` plain, `::` base64, `:<` URL.
    form: Form,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Plain,
    Base64,
    Url,
}

/// Parses one record, or nothing when it turned out to be empty.
fn parse_record(physical: &Physical) -> Result<Option<Record>, Error> {
    let mut lines = Vec::with_capacity(physical.lines.len());

    for (number, text) in &physical.lines {
        if text.is_empty() {
            return Err(Error::OrphanContinuation {
                line: *number,
                text: String::new(),
            });
        }
        lines.push(parse_line(*number, text)?);
    }

    let Some(first) = lines.first() else {
        return Ok(None);
    };

    if first.name != "dn" {
        return Err(Error::NotADn {
            line: first.number,
            text: first.text.clone(),
        });
    }

    let dn = read_value(first)?;
    let rest = &lines[1..];

    // A `changetype` anywhere after `dn` makes this a change record; without one it is an
    // entry, which is what a plain export contains.
    match rest.iter().position(|line| line.name == "changetype") {
        Some(position) => {
            let change_line = &rest[position];
            let value = read_value(change_line)?;
            let change = match value.trim().to_ascii_lowercase().as_str() {
                "add" => Change::Add,
                "modify" => Change::Modify,
                "delete" => Change::Delete,
                "modrdn" | "moddn" => Change::ModDn,
                other => {
                    return Err(Error::UnknownChangeType {
                        line: change_line.number,
                        value: other.to_string(),
                    });
                }
            };

            parse_change(physical, dn, change, change_line.number, rest)
        }
        None => {
            let mut attributes = Attributes::new();
            for line in rest {
                // `-` separates the specifications of a modify record; in an entry it is a
                // line that means nothing, and reading it as an attribute called "-" would
                // import a file that mixes two record forms.
                if line.name == "-" {
                    return Err(Error::NotAnAttribute {
                        line: line.number,
                        text: "-".to_string(),
                    });
                }

                attributes = add_value(attributes, line)?;
            }

            Ok(Some(Record::Entry(Content {
                entry: Entry::new(dn, attributes),
            })))
        }
    }
}

/// Parses the lines of a change record.
///
/// `changetype: add` is handled apart from the rest: RFC 2849 §3.5 makes such a record carry
/// its attributes exactly as a content record does, so it becomes an entry rather than a
/// change with modifications. Collapsing the two here means every consumer has one shape to
/// handle for "add this entry", which is what the protocol has too.
fn parse_change(
    physical: &Physical,
    dn: String,
    change: Change,
    change_line: usize,
    rest: &[Line],
) -> Result<Option<Record>, Error> {
    let mut modifications: Vec<Modification> = Vec::new();
    if change == Change::Add {
        let mut attributes = Attributes::new();
        for line in rest {
            if line.name == "changetype" {
                continue;
            }
            attributes = add_value(attributes, line)?;
        }

        return Ok(Some(Record::Entry(Content {
            entry: Entry::new(dn, attributes),
        })));
    }

    let mut new_rdn = None;
    let mut delete_old_rdn = None;
    let mut new_superior = None;

    for line in rest {
        match line.name.as_str() {
            "changetype" => {}
            "newrdn" => new_rdn = Some(read_value(line)?),
            "newsuperior" => new_superior = Some(read_value(line)?),
            "deleteoldrdn" => {
                let value = read_value(line)?;
                delete_old_rdn = Some(match value.trim() {
                    "0" => false,
                    "1" => true,
                    other => {
                        return Err(Error::BadDeleteOldRdn {
                            line: line.number,
                            value: other.to_string(),
                        });
                    }
                });
            }
            // `-` separates the specifications of a modify; anywhere else it is a line that
            // means nothing, and a file that mixed the two forms is not one to guess about.
            "-" => {
                if change != Change::Modify {
                    return Err(Error::NotAnAttribute {
                        line: line.number,
                        text: "-".to_string(),
                    });
                }
            }
            "add" | "delete" | "replace" => {
                let op = match line.name.as_str() {
                    "add" => ModOp::Add,
                    "delete" => ModOp::Delete,
                    _ => ModOp::Replace,
                };
                modifications.push(Modification {
                    op,
                    attribute: read_value(line)?,
                    values: Vec::new(),
                });
            }
            other => {
                // A value belongs to the specification above it.
                let Some(current) = modifications.last_mut() else {
                    return Err(Error::ValueBeforeOperator {
                        line: line.number,
                        name: other.to_string(),
                    });
                };

                if current.attribute != other {
                    return Err(Error::ValueBeforeOperator {
                        line: line.number,
                        name: other.to_string(),
                    });
                }

                current.values.push(read_value(line)?);
            }
        }
    }

    let _ = physical;

    match change {
        Change::Modify if modifications.is_empty() => Err(Error::EmptyModify { line: change_line }),
        Change::ModDn if new_rdn.is_none() => Err(Error::MissingNewRdn { line: change_line }),
        _ => Ok(Some(Record::Change(ChangeRecord {
            dn,
            change,
            modifications,
            new_rdn,
            delete_old_rdn,
            new_superior,
        }))),
    }
}

/// Splits `name: value`, `name:: base64` or `name:< url`.
fn parse_line(number: usize, text: &str) -> Result<Line, Error> {
    // `-` is a separator, not an attribute: it has no colon at all.
    if text == "-" {
        return Ok(Line {
            number,
            name: "-".to_string(),
            form: Form::Plain,
            text: String::new(),
        });
    }

    let Some((name, rest)) = text.split_once(':') else {
        return Err(Error::NotAnAttribute {
            line: number,
            text: text.to_string(),
        });
    };

    if name.is_empty() || name.contains(' ') {
        return Err(Error::NotAnAttribute {
            line: number,
            text: text.to_string(),
        });
    }

    // `::` is base64, `:<` is a URL, and a single space after the colon is the separator.
    let (form, rest) = if let Some(value) = rest.strip_prefix(':') {
        (Form::Base64, value)
    } else if let Some(value) = rest.strip_prefix('<') {
        (Form::Url, value)
    } else {
        (Form::Plain, rest)
    };

    // Exactly one space separates the colon from the value; a second one is part of it.
    let text = rest.strip_prefix(' ').unwrap_or(rest).to_string();

    Ok(Line {
        number,
        name: name.to_string(),
        form,
        text,
    })
}

/// The value of a line, decoded according to its form.
fn read_value(line: &Line) -> Result<String, Error> {
    match line.form {
        Form::Plain => Ok(line.text.clone()),
        Form::Base64 => {
            let bytes = decode_base64(&line.text).map_err(|detail| Error::Base64 {
                line: line.number,
                name: line.name.clone(),
                detail,
            })?;

            String::from_utf8(bytes).map_err(|err| Error::Base64 {
                line: line.number,
                name: line.name.clone(),
                detail: format!("the value is not valid UTF-8: {err}"),
            })
        }
        Form::Url => {
            let url = line.text.trim();
            let Some(path) = url.strip_prefix("file://") else {
                return Err(Error::UnsupportedUrl {
                    line: line.number,
                    url: url.to_string(),
                });
            };

            let bytes = std::fs::read(path).map_err(|err| Error::Url {
                line: line.number,
                name: line.name.clone(),
                url: url.to_string(),
                detail: err.to_string(),
            })?;

            String::from_utf8(bytes).map_err(|err| Error::Url {
                line: line.number,
                name: line.name.clone(),
                url: url.to_string(),
                detail: format!("the file is not valid UTF-8: {err}"),
            })
        }
    }
}

/// Appends one value to the attribute of that name, creating it when it is new.
fn add_value(mut attributes: Attributes, line: &Line) -> Result<Attributes, Error> {
    let value = read_value(line)?;

    match attributes
        .values()
        .iter()
        .position(|attribute| attribute.name.eq_ignore_ascii_case(&line.name))
    {
        Some(index) => {
            // A repeated attribute adds a value rather than replacing it: `objectClass`
            // appears several times in every real entry.
            let mut values: Vec<String> = attributes.values()[index].values.to_vec();
            values.push(value);
            attributes = attributes.replace(Attribute::new(&line.name, values));
        }
        None => attributes = attributes.push(Attribute::new(&line.name, vec![value])),
    }

    Ok(attributes)
}

/// Base64, the standard alphabet with padding.
///
/// Written out rather than pulled in: the crate has no base64 dependency, this is forty
/// lines, and the decoder has to reject what the encoder would never produce - a length that
/// is not a multiple of four, a character outside the alphabet - which is where a lenient
/// decoder turns a corrupted file into a wrong value.
fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let bytes: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();

    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(format!(
            "the length {} is not a multiple of four",
            bytes.len()
        ));
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    // Padding ends the value (RFC 4648 §3.2). `YQ==YQ==` decodes to "aa" under a decoder that
    // only checks each group on its own, and "aa" is a plausible password for a file that was
    // corrupted on the way here.
    let mut ended = false;

    for chunk in bytes.chunks(4) {
        if ended {
            return Err("padding appears before the end of the value".to_string());
        }

        let mut accumulator = 0u32;
        let mut padding = 0;

        for (index, byte) in chunk.iter().enumerate() {
            let value = if *byte == b'=' {
                // Padding is only legal in the last two positions.
                if index < 2 {
                    return Err("padding in the middle of a group".to_string());
                }
                padding += 1;
                0
            } else {
                ALPHABET
                    .iter()
                    .position(|candidate| candidate == byte)
                    .ok_or_else(|| format!("'{}' is not a base64 character", *byte as char))?
                    as u32
            };

            accumulator = (accumulator << 6) | value;
        }

        if padding > 0 {
            ended = true;
        }

        let triple = accumulator.to_be_bytes();
        out.push(triple[1]);
        if padding < 2 {
            out.push(triple[2]);
        }
        if padding < 1 {
            out.push(triple[3]);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::decode_base64;

    #[test]
    fn base64_round_trips_the_shapes_that_matter() {
        // The three padding lengths, plus a value that is pure ASCII.
        assert_eq!(decode_base64("").expect("empty"), b"");
        assert_eq!(decode_base64("YQ==").expect("one"), b"a");
        assert_eq!(decode_base64("YWI=").expect("two"), b"ab");
        assert_eq!(decode_base64("YWJj").expect("three"), b"abc");
        assert_eq!(decode_base64("aGVsbG8=").expect("hello"), b"hello");
    }

    #[test]
    fn a_length_that_is_not_a_multiple_of_four_is_refused() {
        assert!(decode_base64("YWJ").is_err());
    }

    #[test]
    fn a_character_outside_the_alphabet_is_refused_and_named() {
        let err = decode_base64("YW*j").expect_err("must refuse");
        assert!(err.contains('*'), "{err}");
    }

    #[test]
    fn padding_in_the_middle_is_refused() {
        assert!(decode_base64("YQ==YQ==").is_err());
    }

    #[test]
    fn whitespace_inside_the_value_is_ignored() {
        // A folded base64 value arrives with its fold already removed here, but a hand-edited
        // file may still carry spaces; they are not part of the alphabet.
        assert_eq!(decode_base64("YWJ j").expect("spaces"), b"abc");
    }
}
