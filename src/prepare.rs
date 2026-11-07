//! String preparation for matching: RFC 4518, which is what makes two values comparable.
//!
//! The rule this replaces was `value.to_lowercase()`, and it is not an approximation to a matching
//! rule — it is a different rule that happens to agree on ASCII. Three things it gets wrong, each of
//! which changes an answer rather than a speed:
//!
//! * `й` written as one code point (NFC) and as `и` plus a combining breve (NFD) are two different
//!   byte strings. Searching for one does not find the other. Same for `ё`, `é`, and every
//!   Latin-with-diacritic name a real directory holds.
//! * `ß` lowercases to `ß`, but `caseIgnoreMatch` must treat it as `ss`. `to_lowercase` does not.
//! * A full-width `Ａ`, a ligature `ﬁ` and a non-breaking space are all characters a client may
//!   send and expect to match their ordinary forms. `to_lowercase` leaves them alone.
//!
//! # The six steps, and what this module does with each
//!
//! RFC 4518 §2 fixes the order, and the order is not arbitrary:
//!
//! 1. **Transcode** — nothing to do: the protocol is UTF-8 and Rust strings are UTF-8.
//! 2. **Map** — soft hyphens, control characters and zero-width joiners go to nothing; tabs and line
//!    breaks go to a space; every separator becomes a space; and **case folding** happens here, per
//!    RFC 3454 B.2.
//! 3. **Normalize** — to Form KC, *after* the fold. Doing it the other way round loses the four-fold
//!    mappings that produce new characters.
//! 4. **Prohibit** — unassigned, private-use, non-character, surrogate and `U+FFFD` code points make
//!    the whole assertion undefined rather than merely unmatched.
//! 5. **Check bidi** — ignored by the RFC itself ("Bidirectional characters are ignored").
//! 6. **Insignificant space handling** — §2.6.1: a string becomes ` foo  bar ` if it has anything
//!    but spaces in it, and exactly two spaces if it does not.
//!
//! # Two deliberate departures, both in the same direction
//!
//! * The table of unassigned code points is Unicode **3.2** (RFC 3454 A.1). Twenty years later that
//!   snapshot would prohibit a great deal that is now ordinary. This module does not check it: it
//!   accepts more than the RFC does, and never compares differently.
//! * The repertoire is the Unicode version of the normalisation crate, not 3.2. Every character
//!   assigned since then is folded and normalised by the same rules, which is what a modern client
//!   expects and what 389 DS, OpenLDAP and every other implementation shipped in the last two
//!   decades does.
//!
//! Both departures are recorded in `docs/ub-log.md` with the reason, not only here.
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;

/// A code point the RFC prohibits, with where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prohibited {
    pub code_point: char,
    pub why: &'static str,
}

impl std::fmt::Display for Prohibited {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "U+{:04X} is prohibited by RFC 4518 ({}), so the comparison is undefined",
            self.code_point as u32, self.why
        )
    }
}

impl std::error::Error for Prohibited {}

/// Which matching rule a string is being prepared for.
///
/// The rule decides two things: whether case is folded, and which characters count as insignificant.
/// `caseExactMatch` keeps case and handles spaces exactly as `caseIgnoreMatch` does - that is the
/// RFC's own pairing, not a simplification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    CaseIgnore,
    CaseExact,
    /// `numericStringMatch`: all spaces are removed (§2.6.2).
    NumericString,
    /// `telephoneNumberMatch`: spaces and hyphens are removed (§2.6.3).
    TelephoneNumber,
}

impl Rule {
    fn folds_case(self) -> bool {
        matches!(self, Self::CaseIgnore)
    }
}

/// Where a part of a substring assertion sits, which changes its space handling (§2.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Initial,
    Any,
    Final,
}

/// Prepares a string for comparison: the six steps of RFC 4518.
pub fn prepare(value: &str, rule: Rule) -> Result<String, Prohibited> {
    let mapped = map(value);
    let folded = if rule.folds_case() {
        fold_case(&mapped)
    } else {
        mapped
    };
    let normalized: String = folded.nfkc().collect();

    prohibit(&normalized)?;

    Ok(match rule {
        Rule::NumericString => remove_all(&normalized, |character| {
            character == ' ' || character == '-'
        }),
        Rule::TelephoneNumber => remove_all(&normalized, |character| {
            character == ' ' || is_hyphen(character)
        }),
        Rule::CaseIgnore | Rule::CaseExact => insignificant_spaces(&normalized),
    })
}

/// Prepares one part of a substring assertion.
///
/// The parts are prepared for matching `caseIgnoreSubstringsMatch` and its exact twin. Their space
/// handling differs from a whole value's on purpose: an *initial* part keeps one leading space and an
/// *any* part keeps none, because the RFC's rule is that a partition of a value must match the
/// assertion however it is subdivided (§2.6, Appendix B).
pub fn prepare_part(part: &str, rule: Rule, position: Position) -> Result<String, Prohibited> {
    let mapped = map(part);
    let folded = if rule.folds_case() {
        fold_case(&mapped)
    } else {
        mapped
    };
    let normalized: String = folded.nfkc().collect();

    prohibit(&normalized)?;

    let mut part = collapse_spaces(&normalized);

    // §2.6.1, and the asymmetry is the point: a *prepared value* carries one space at each end, so
    // an initial part must carry one at the start to line up with it, and a final part one at the
    // end. Getting this wrong makes `(cn=ali*)` miss `alice` - which is what the first version of
    // this function did, and what a test now pins.
    match position {
        Position::Initial => {
            if !part.starts_with(' ') {
                part.insert(0, ' ');
            }
        }
        Position::Any => {}
        Position::Final => {
            if !part.ends_with(' ') {
                part.push(' ');
            }
        }
    }

    Ok(part)
}

/// RFC 4518 §2.2: what each character class becomes before anything else happens.
fn map(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            // Mapped to nothing: characters that are an artefact of text reproduction rather than
            // of the text.
            '\u{00AD}' | '\u{1806}' | '\u{034F}' | '\u{FFFC}' | '\u{200B}' => {}
            '\u{180B}'..='\u{180D}' | '\u{FE00}'..='\u{FE0F}' => {}
            // Mapped to a space: every kind of whitespace a client might have typed.
            '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | '\u{0085}' => out.push(' '),
            ' '
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}' => out.push(' '),
            // Everything else with a control function, mapped to nothing.
            '\u{0000}'..='\u{0008}'
            | '\u{000E}'..='\u{001F}'
            | '\u{007F}'..='\u{0084}'
            | '\u{0086}'..='\u{009F}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{180E}'
            | '\u{200C}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2063}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}' => {}
            other => out.push(other),
        }
    }
    out
}

/// RFC 3454 B.2 full case folding: `ß` becomes `ss`, `ﬁ` becomes `fi`, and case is erased.
fn fold_case(value: &str) -> String {
    // C and F mappings together: full folding, which is what makes `ß` two letters. The simple
    // mapping alone would leave it alone, and that is the difference `to_lowercase` got wrong.
    caseless::default_case_fold_str(value)
}

/// RFC 4518 §2.4: code points that make an assertion undefined rather than merely unmatched.
fn prohibit(value: &str) -> Result<(), Prohibited> {
    for character in value.chars() {
        let why = match character as u32 {
            // Private use: never a shared value, so never comparable with one.
            0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD => "private use",
            // Non-characters: reserved forever, so a match on one means nothing.
            0xFDD0..=0xFDEF => "a non-character",
            0xFFFD => "the replacement character, which marks a decoding failure rather than text",
            _ if (character as u32) & 0xFFFE == 0xFFFE => "a non-character",
            // RFC 3454 C.8: characters that change display properties or are deprecated.
            0x0340 | 0x0341 | 0x200E | 0x200F => "it changes display properties",
            0x202A..=0x202E | 0x206A..=0x206F => "it changes display properties",
            _ => continue,
        };
        return Err(Prohibited {
            code_point: character,
            why,
        });
    }
    Ok(())
}

/// RFC 4518 §2.6.1 for a whole value or an equality assertion.
///
/// ` foo  bar ` and not `foo bar`: the RFC keeps one space at each end and turns every inner run into
/// exactly two. It looks odd and it is what makes substring preparation consistent (§2.6, Appendix
/// B): a value's own edges are insignificant, and an inner space is significant enough to survive
/// being split by a substring assertion.
fn insignificant_spaces(value: &str) -> String {
    let collapsed = collapse_spaces(value);
    let trimmed = collapsed.trim_matches(' ');
    if trimmed.is_empty() {
        // A string of nothing but spaces still has to compare equal to another one.
        return "  ".to_string();
    }
    format!(" {} ", trimmed)
}

/// Every run of spaces becomes exactly two, and the edges keep one if they had any.
///
/// The `space` of the RFC is "SPACE followed by no combining mark", so a space that carries a mark is
/// not a separator: it is a base character that happens to look like one, and folding it into a
/// separator would merge two distinct values.
fn collapse_spaces(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut at = 0;

    while at < characters.len() {
        if is_space(&characters, at) {
            // Count the run, so an inner run becomes two and an edge run becomes one.
            let mut end = at;
            while end < characters.len() && is_space(&characters, end) {
                end += 1;
            }
            let at_edge = at == 0 || end == characters.len();
            if at_edge {
                out.push(' ');
            } else {
                out.push_str("  ");
            }
            at = end;
        } else {
            out.push(characters[at]);
            at += 1;
        }
    }

    out
}

/// Whether the character at `at` is the RFC's space: `U+0020` with no combining mark after it.
fn is_space(characters: &[char], at: usize) -> bool {
    if characters[at] != ' ' {
        return false;
    }
    match characters.get(at + 1) {
        Some(next) => !is_combining_mark(*next),
        None => true,
    }
}

fn is_hyphen(character: char) -> bool {
    matches!(
        character,
        '-' | '\u{058A}' | '\u{2010}' | '\u{2011}' | '\u{2212}' | '\u{FE63}' | '\u{FF0D}'
    )
}

fn remove_all(value: &str, drop: impl Fn(char) -> bool) -> String {
    value
        .chars()
        .filter(|character| !drop(*character))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ignore(value: &str) -> String {
        prepare(value, Rule::CaseIgnore).expect("prepared")
    }

    #[test]
    fn case_is_folded_before_anything_else_is_decided() {
        assert_eq!(ignore("Ann"), " ann ");
        assert_eq!(ignore("ANN"), " ann ");
        assert_eq!(ignore("ann"), " ann ");
        // Not by lowercasing alone: the RFC's fold turns the sharp s into two letters, which is what
        // makes `Straße` and `STRASSE` the same value.
        assert_eq!(ignore("Straße"), ignore("STRASSE"));
        // And a ligature, which `to_lowercase` would have left as one character.
        assert_eq!(ignore("ﬁle"), ignore("file"));
    }

    #[test]
    fn the_same_name_written_two_ways_compares_equal() {
        // The defect this module exists for: NFC `й` is one code point, NFD `й` is two, and the byte
        // strings differ. A directory that compares bytes misses one of them forever.
        let composed = "Йошкар-Ола";
        let decomposed = "И\u{0306}ошкар-Ола";
        assert_ne!(composed, decomposed, "different strings, same word");
        assert_eq!(ignore(composed), ignore(decomposed));

        // The same for an accented Latin name, which is the common case outside Russia.
        let composed = "José";
        let decomposed = "Jose\u{0301}";
        assert_eq!(ignore(composed), ignore(decomposed));
    }

    #[test]
    fn a_wide_or_compatibility_character_matches_its_ordinary_form() {
        // Form KC is what does this, and the RFC asks for KC and not C precisely here.
        assert_eq!(ignore("Ａｎｎ"), ignore("Ann"));
        assert_eq!(ignore("①"), ignore("1"));
    }

    #[test]
    fn spaces_become_one_at_the_edges_and_two_inside() {
        assert_eq!(ignore("foo bar"), " foo  bar ");
        assert_eq!(ignore("  foo   bar  "), " foo  bar ");
        assert_eq!(ignore("foo"), " foo ");
        // A value of nothing but spaces is still a value.
        assert_eq!(ignore("   "), "  ");
        // A non-breaking space is a space: a client that pasted one from a web form still matches.
        assert_eq!(ignore("foo\u{00A0}bar"), " foo  bar ");
    }

    #[test]
    fn invisible_characters_are_removed_rather_than_compared() {
        // A soft hyphen is what a word processor inserts at a line break; it is not part of the word.
        assert_eq!(ignore("An\u{00AD}n"), ignore("Ann"));
        // A zero-width space likewise, and a byte-order mark that leaked into a value.
        assert_eq!(ignore("An\u{200B}n"), ignore("Ann"));
        assert_eq!(ignore("\u{FEFF}Ann"), ignore("Ann"));
        // A tab is a space, not nothing: removing it would join two words into one.
        assert_eq!(ignore("foo\tbar"), " foo  bar ");
    }

    #[test]
    fn a_prohibited_code_point_makes_the_comparison_undefined() {
        let refused = prepare("bad\u{FFFD}", Rule::CaseIgnore).expect_err("refused");
        assert!(refused.to_string().contains("FFFD"), "{refused}");

        // Private use and non-characters are refused. The deprecated display characters of RFC 3454
        // C.8 are not tested here because they never reach this check: step 2 of the RFC maps most of
        // them to nothing and Form KC decomposes the rest, which is the RFC's own order doing the
        // work - the prohibition is a backstop, not the mechanism.
        assert!(prepare("x\u{E000}", Rule::CaseIgnore).is_err());
        assert!(prepare("x\u{FDD0}", Rule::CaseIgnore).is_err());
        assert!(prepare("x\u{10FFFF}", Rule::CaseIgnore).is_err());
    }

    #[test]
    fn case_exact_keeps_the_case_and_handles_spaces_the_same_way() {
        let exact = |value: &str| prepare(value, Rule::CaseExact).expect("prepared");

        assert_ne!(exact("Ann"), exact("ann"), "case is the point of the rule");
        assert_eq!(
            exact("Ann"),
            exact(" Ann  "),
            "spaces are still insignificant"
        );
        // Normalisation still happens under the exact rule; only case folding does not.
        assert_eq!(
            exact("\u{0418}\u{0306}ошкар"),
            exact("\u{0419}ошкар"),
            "and normalisation still happens"
        );
    }

    #[test]
    fn a_numeric_string_loses_every_space_and_a_telephone_number_its_hyphens() {
        assert_eq!(
            prepare(" 123 456 ", Rule::NumericString).expect("prepared"),
            "123456"
        );
        assert_eq!(
            prepare(" +7 916 123-45-67 ", Rule::TelephoneNumber).expect("prepared"),
            "+791612345 67".replace(' ', "")
        );
    }

    #[test]
    fn a_substring_part_is_prepared_without_the_space_it_does_not_own() {
        // An initial part starts the value, so it cannot be preceded by a space; an any part can.
        let initial = prepare_part("Ann", Rule::CaseIgnore, Position::Initial).expect("prepared");
        let any = prepare_part("Ann", Rule::CaseIgnore, Position::Any).expect("prepared");
        let final_part = prepare_part("Ann", Rule::CaseIgnore, Position::Final).expect("prepared");

        // A prepared value is ` ann `; an initial part has to line up with its leading space and a
        // final part with its trailing one, or the substring would not match it.
        assert_eq!(
            initial, " ann",
            "an initial part carries the value's leading space"
        );
        assert_eq!(
            final_part, "ann ",
            "a final part carries its trailing space"
        );
        assert_eq!(
            any, "ann",
            "an any part carries no edge space it did not have"
        );
    }

    #[test]
    fn a_space_carrying_a_combining_mark_is_a_character_and_not_a_separator() {
        // The RFC defines its space as SPACE followed by no combining mark. A space with one is a
        // different thing, and folding it into a separator would merge two distinct values.
        let with_mark = "a \u{0301}b";
        let prepared = ignore(with_mark);
        assert!(
            prepared.contains('\u{0301}'),
            "the mark must survive: {prepared:?}"
        );
    }
}
