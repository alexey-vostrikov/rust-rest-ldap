//! Operational attributes the server writes: when, by whom, and in what order.
//!
//! `createTimestamp`, `modifyTimestamp`, `creatorsName`, `modifiersName` and
//! `entryCSN` (RFC 4512 §3.4, OpenLDAP's CSN form) are maintained here rather than by
//! the backend: they describe the write, and only the layer that knows who is writing
//! and when can fill them honestly.
//!
//! `entryCSN` is the reason the format matters. It is a change sequence number that
//! sorts: `20261102143012.123456Z#000042#000#000000` is later than `…#000041#…`
//! because the counter is fixed-width. Anything that keeps this property can order
//! two changes that arrived in the same microsecond, which a plain timestamp cannot.
//!
//! Two rules that make the values trustworthy:
//! - `createTimestamp` is never overwritten. A modify is not a creation.
//! - An entry that arrives from a backend without these attributes gets them on its
//!   first write, not at load: claiming the file's mtime was the creation time would
//!   be a guess dressed up as data.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{Attribute, Entry};

pub const ATTR_CREATE_TIMESTAMP: &str = "createTimestamp";
pub const ATTR_MODIFY_TIMESTAMP: &str = "modifyTimestamp";
pub const ATTR_CREATORS_NAME: &str = "creatorsName";
pub const ATTR_MODIFIERS_NAME: &str = "modifiersName";
pub const ATTR_ENTRY_CSN: &str = "entryCSN";

/// Counter that keeps CSNs distinct and ordered within one microsecond.
static CSN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Stamps a write on `entry`.
///
/// `actor` is the DN of the bound user performing the change; `now` is passed in so
/// tests can pin it. The result is a new entry: the caller persists it, and the
/// previous snapshot stays as it was.
pub fn stamp_write(entry: &Entry, actor: &str, now: SystemTime) -> Entry {
    let timestamp = generalized_time(now);
    let mut attributes = entry.attributes().clone();

    // First write of an entry that nothing has stamped yet: this is also its creation
    // as far as the server is concerned.
    if attributes.get(ATTR_CREATE_TIMESTAMP).is_none() {
        attributes = attributes
            .push(Attribute::single(ATTR_CREATE_TIMESTAMP, &timestamp).operational())
            .push(Attribute::single(ATTR_CREATORS_NAME, actor).operational());
    }

    // `replace`, not `push`: a second write must move the value, not add a second one.
    attributes = attributes
        .replace(Attribute::single(ATTR_MODIFY_TIMESTAMP, &timestamp).operational())
        .replace(Attribute::single(ATTR_MODIFIERS_NAME, actor).operational())
        .replace(Attribute::single(ATTR_ENTRY_CSN, &change_sequence_number(now)).operational());

    Entry::new(entry.dn(), attributes)
}

/// `YYYYmmddHHMMSS.mmmmmmZ`, the generalized time OpenLDAP writes.
///
/// RFC 4517 allows the fractional part, and it is what makes two writes in the same
/// second distinguishable in a log.
pub fn generalized_time(at: SystemTime) -> String {
    let micros = at
        .duration_since(UNIX_EPOCH)
        // A clock before 1970 cannot be represented; the epoch is the honest floor.
        .map(|elapsed| elapsed.as_micros() as i64)
        .unwrap_or(0);

    let seconds = micros.div_euclid(1_000_000);
    let fraction = micros.rem_euclid(1_000_000);
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = time_of_day / 3_600;
    let minute = (time_of_day % 3_600) / 60;
    let second = time_of_day % 60;

    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}.{fraction:06}Z")
}

/// Parses the form [`generalized_time`] writes, so a stored value can be ordered.
pub fn parse_generalized_time(text: &str) -> Option<SystemTime> {
    let body = text.strip_suffix('Z')?;
    let (main, fraction) = match body.split_once('.') {
        Some((main, fraction)) => (main, fraction),
        None => (body, ""),
    };
    if main.len() != 14 || !main.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !fraction.is_empty() && !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let number = |range: std::ops::Range<usize>| main[range].parse::<i64>().ok();
    let year = number(0..4)?;
    let month = number(4..6)?;
    let day = number(6..8)?;
    let hour = number(8..10)?;
    let minute = number(10..12)?;
    let second = number(12..14)?;

    let micros: i64 = if fraction.is_empty() {
        0
    } else {
        let mut digits = fraction.to_string();
        digits.truncate(6);
        while digits.len() < 6 {
            digits.push('0');
        }
        digits.parse().ok()?
    };

    let days = days_from_civil(year, month as u32, day as u32);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    let micros = seconds * 1_000_000 + micros;

    Some(UNIX_EPOCH + std::time::Duration::from_micros(micros.max(0) as u64))
}

/// `20261102143012.123456Z#000042#000#000000`.
fn change_sequence_number(at: SystemTime) -> String {
    let counter = CSN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}#{counter:06}#{:03}#000000", generalized_time(at), 0)
}

/// Civil date from days since the epoch (Howard Hinnant's algorithm).
///
/// Written out rather than pulled in as a dependency: it is fifteen lines, it has no
/// failure mode, and a date library would be the largest thing in the module.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    let year = if month <= 2 { year + 1 } else { year };

    (year, month, day)
}

/// The inverse of [`civil_from_days`].
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let month = i64::from(month);
    let day = i64::from(day);
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attributes;

    fn at(text: &str) -> SystemTime {
        parse_generalized_time(text).expect("parse")
    }

    fn entry() -> Entry {
        Entry::new(
            "cn=ann,ou=users,dc=example,dc=com",
            Attributes::new()
                .push(Attribute::single("cn", "ann"))
                .push(Attribute::single("sn", "Doe")),
        )
    }

    fn value(entry: &Entry, name: &str) -> Option<String> {
        entry
            .attributes()
            .get(name)
            .and_then(|attribute| attribute.values.first().cloned())
    }

    #[test]
    fn a_known_instant_has_a_known_spelling() {
        assert_eq!(
            generalized_time(at("20261102143012.123456Z")),
            "20261102143012.123456Z"
        );
        assert_eq!(
            generalized_time(at("19700101000000.000000Z")),
            "19700101000000.000000Z"
        );
        assert_eq!(
            generalized_time(at("20000229010203.000004Z")),
            "20000229010203.000004Z",
            "a leap day must round-trip"
        );
    }

    #[test]
    fn dates_are_not_off_by_a_day_at_the_boundaries() {
        for text in [
            "20261231235959.999999Z",
            "20270101000000.000000Z",
            "19991231235959.000000Z",
            "20240229000000.000000Z",
            "20250301000000.000000Z",
        ] {
            assert_eq!(generalized_time(at(text)), text, "{text}");
        }
    }

    #[test]
    fn civil_days_round_trip() {
        for days in [-1_000, 0, 1, 19_000, 20_000, 100_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days, "{days}");
        }
    }

    #[test]
    fn an_unparsable_timestamp_is_rejected() {
        assert_eq!(parse_generalized_time("2026-11-02"), None);
        assert_eq!(parse_generalized_time("20261102143012"), None, "no Z");
        assert_eq!(parse_generalized_time("2026110214301a.000000Z"), None);
        assert_eq!(parse_generalized_time("20261102143012.abcZ"), None);
    }

    #[test]
    fn a_first_write_stamps_creation_and_modification() {
        let stamped = stamp_write(
            &entry(),
            "cn=admin,dc=example,dc=com",
            at("20261102143012.000001Z"),
        );

        assert_eq!(
            value(&stamped, ATTR_CREATE_TIMESTAMP).as_deref(),
            Some("20261102143012.000001Z")
        );
        assert_eq!(
            value(&stamped, ATTR_CREATORS_NAME).as_deref(),
            Some("cn=admin,dc=example,dc=com")
        );
        assert_eq!(
            value(&stamped, ATTR_MODIFY_TIMESTAMP).as_deref(),
            Some("20261102143012.000001Z")
        );
        assert_eq!(
            value(&stamped, ATTR_MODIFIERS_NAME).as_deref(),
            Some("cn=admin,dc=example,dc=com")
        );
        assert!(value(&stamped, ATTR_ENTRY_CSN).is_some());
    }

    #[test]
    fn a_second_write_keeps_the_creation_and_moves_the_modification() {
        let first = stamp_write(
            &entry(),
            "cn=admin,dc=example,dc=com",
            at("20261102143012.000001Z"),
        );
        let second = stamp_write(
            &first,
            "cn=ann,ou=users,dc=example,dc=com",
            at("20261102150000.000002Z"),
        );

        assert_eq!(
            value(&second, ATTR_CREATE_TIMESTAMP),
            value(&first, ATTR_CREATE_TIMESTAMP),
            "a modify is not a creation"
        );
        assert_eq!(
            value(&second, ATTR_CREATORS_NAME).as_deref(),
            Some("cn=admin,dc=example,dc=com"),
            "the creator does not become the modifier"
        );
        assert_eq!(
            value(&second, ATTR_MODIFY_TIMESTAMP).as_deref(),
            Some("20261102150000.000002Z")
        );
        assert_eq!(
            value(&second, ATTR_MODIFIERS_NAME).as_deref(),
            Some("cn=ann,ou=users,dc=example,dc=com")
        );
    }

    #[test]
    fn the_change_sequence_numbers_sort() {
        let first = change_sequence_number(at("20261102143012.000001Z"));
        let second = change_sequence_number(at("20261102143012.000001Z"));
        let later = change_sequence_number(at("20261102143012.000002Z"));

        assert!(
            first < second,
            "same microsecond still orders: {first} < {second}"
        );
        assert!(second < later, "a later time orders: {second} < {later}");
        assert_eq!(
            first.len(),
            later.len(),
            "fixed width, so text comparison works"
        );
    }

    #[test]
    fn the_stamped_attributes_are_operational() {
        let stamped = stamp_write(
            &entry(),
            "cn=admin,dc=example,dc=com",
            at("20261102143012.000001Z"),
        );

        for name in [
            ATTR_CREATE_TIMESTAMP,
            ATTR_MODIFY_TIMESTAMP,
            ATTR_CREATORS_NAME,
            ATTR_MODIFIERS_NAME,
            ATTR_ENTRY_CSN,
        ] {
            let attribute = stamped.attributes().get(name).expect(name);
            assert!(attribute.flags.operational, "{name} must be operational");
        }
    }

    #[test]
    fn the_entry_keeps_its_own_attributes_and_dn() {
        let stamped = stamp_write(
            &entry(),
            "cn=admin,dc=example,dc=com",
            at("20261102143012.000001Z"),
        );

        assert_eq!(stamped.dn(), entry().dn());
        assert_eq!(value(&stamped, "cn").as_deref(), Some("ann"));
        assert_eq!(value(&stamped, "sn").as_deref(), Some("Doe"));
    }

    #[test]
    fn stamping_twice_does_not_duplicate_attributes() {
        let once = stamp_write(
            &entry(),
            "cn=admin,dc=example,dc=com",
            at("20261102143012.000001Z"),
        );
        let twice = stamp_write(
            &once,
            "cn=admin,dc=example,dc=com",
            at("20261102143012.000002Z"),
        );

        for name in [
            ATTR_CREATE_TIMESTAMP,
            ATTR_MODIFY_TIMESTAMP,
            ATTR_CREATORS_NAME,
            ATTR_MODIFIERS_NAME,
            ATTR_ENTRY_CSN,
        ] {
            assert_eq!(
                twice
                    .attributes()
                    .values()
                    .iter()
                    .filter(|attribute| attribute.name.eq_ignore_ascii_case(name))
                    .count(),
                1,
                "{name} must appear once"
            );
        }
    }
}
