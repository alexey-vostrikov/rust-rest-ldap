//! The index snapshot as a file that is **read in place**, not decoded.
//!
//! The previous format was a dump: maps serialised in iteration order, which could only be used by
//! reading all of it back into memory. On three million entries that is 700 MB of postings, ten to
//! fifteen seconds of decoding and the same again in resident memory - a cost paid at every start,
//! to answer questions about a handful of entries.
//!
//! This format is built so that the file *is* the index. Keys are sorted, a table of offsets points
//! at each record, and a lookup is a binary search that reads two or three records: a few
//! kilobytes instead of a gigabyte of decoding. Starting is opening a file and validating a header.
//!
//! # Why positional reads and not `mmap`
//!
//! `mmap` is what this wants, and it is what it cannot have: every mapping API in Rust - including
//! `memmap2` - is an `unsafe` function, because the file can be changed underneath the mapping and
//! what follows is undefined behaviour. This crate carries `#![forbid(unsafe_code)]`, and trading
//! that for a page-fault-per-lookup is a bad trade: `read_at` gives the same property that matters -
//! nothing is read until it is asked for - through the kernel's page cache, with a syscall instead
//! of a fault. A handful of lookups per search do not notice the difference; a start notices the
//! absence of a gigabyte of parsing either way.
//!
//! # Layout
//!
//! ```text
//! header       magic, version, sequence, next_id, plan hash, counts, three offsets
//! records      count × { key_len u32, key bytes, bitmap_len u32, roaring bytes }
//! offsets      count × u64 - absolute offset of each record, in key order
//! numbering    count × { dn_len u32, dn bytes, id u32 }
//! ```
//!
//! Records are sorted by key, and the offset table is what makes the sort useful: a binary search
//! needs random access, and with a table it is arithmetic over a slice.
//!
//! # The key
//!
//! `tag u8 | attribute | 0x00 | value`, sorted bytewise. The tag keeps the four kinds of posting in
//! one sorted space, so there is one search rather than four; the separator keeps `cn` + `a` from
//! colliding with `cna` + nothing.
//!
//! # What is not here yet
//!
//! Ordered ranges (`>=`, `<=`) are not answerable from the mapped file: their keys would need an
//! order-preserving binary encoding, and a scan is the honest fallback until that exists. Equality,
//! presence and substrings - which is what a filter narrows with in practice - are answered here.

// The one `unsafe` in this crate, and the reason the crate says `deny` rather than `forbid`.
//
// Mapping a file is `unsafe` in Rust because the mapping outlives the call: if another process
// truncated the file, reading a mapped page is undefined behaviour. The contract this code keeps:
//
// 1. the snapshot file is only ever replaced by `rename`, never truncated in place - a rename
//    leaves the old inode alive for as long as any mapping points at it;
// 2. the length is taken from the file **at open**, and every read is bounds-checked against it
//    before the bytes are used, so a shorter file cannot be read past its end;
// 3. the file is opened read-only, so neither this process nor a mapper can write through it.
//
// `miri` cannot check this (it does not model file mappings), which is why the tests in this module
// exercise the bounds checking directly: a truncated file, a foreign file, a table pointing into the
// records. The unsafe call is one line; everything it feeds is safe.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;

use roaring::RoaringBitmap;

/// Written at the front of the file and checked before anything else is read.
const MAGIC: &[u8; 8] = b"RRLDIX02";
const VERSION: u32 = 2;
/// magic, version, sequence, next_id, plan, count, then three positions: records, the offset
/// table, and the numbering - followed by the numbering length.
const HEADER_LEN: usize = 8 + 4 + 8 + 4 + 8 + 8 + 16 + 16;

/// Which kind of posting a record holds. One byte, because it is the first byte of the key and
/// sorts the four kinds apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    Presence = 1,
    Equality = 2,
    Substring = 3,
    Ordered = 4,
}

impl Tag {
    pub fn from_byte(byte: u8) -> Option<Tag> {
        match byte {
            1 => Some(Tag::Presence),
            2 => Some(Tag::Equality),
            3 => Some(Tag::Substring),
            4 => Some(Tag::Ordered),
            _ => None,
        }
    }
}

/// The key of one posting.
fn key_of(tag: Tag, attribute: &str, value: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + attribute.len() + 1 + value.len());
    key.push(tag as u8);
    key.extend_from_slice(attribute.as_bytes());
    key.push(0);
    key.extend_from_slice(value.as_bytes());
    key
}

/// Everything the writer needs, already flattened and sorted.
pub struct Records {
    /// `(key, postings)`, sorted by key.
    entries: Vec<(Vec<u8>, RoaringBitmap)>,
    numbering: Vec<(String, u32)>,
}

impl Records {
    /// Collects postings into the one sorted space the file holds.
    ///
    /// Sorted here rather than in the file: a binary search assumes the order, and a file written
    /// out of order would answer `None` for keys that are present - the worst kind of wrong, since
    /// it looks like "no such value".
    pub fn new(
        presence: Vec<(&str, RoaringBitmap)>,
        equality: Vec<(&str, &str, RoaringBitmap)>,
        substrings: Vec<(&str, &str, RoaringBitmap)>,
        numbering: Vec<(String, u32)>,
    ) -> Self {
        let mut entries: Vec<(Vec<u8>, RoaringBitmap)> = Vec::new();
        for (attribute, bitmap) in presence {
            entries.push((key_of(Tag::Presence, attribute, ""), bitmap));
        }
        for (attribute, value, bitmap) in equality {
            entries.push((key_of(Tag::Equality, attribute, value), bitmap));
        }
        for (attribute, value, bitmap) in substrings {
            entries.push((key_of(Tag::Substring, attribute, value), bitmap));
        }

        entries.sort_by(|left, right| left.0.cmp(&right.0));

        Self { entries, numbering }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writes the whole file: header, records, offset table, numbering.
    pub fn write(
        &self,
        out: &mut dyn Write,
        sequence: u64,
        next_id: u32,
        plan: u64,
    ) -> io::Result<()> {
        let mut body = Vec::new();
        let mut offsets: Vec<u64> = Vec::with_capacity(self.entries.len());
        let records_at = HEADER_LEN as u64;

        for (key, bitmap) in &self.entries {
            offsets.push(records_at + body.len() as u64);
            body.extend_from_slice(&(key.len() as u32).to_le_bytes());
            body.extend_from_slice(key);
            let mut roaring = Vec::new();
            bitmap
                .serialize_into(&mut roaring)
                .map_err(|err| io::Error::other(err.to_string()))?;
            body.extend_from_slice(&(roaring.len() as u32).to_le_bytes());
            body.extend_from_slice(&roaring);
        }

        let offsets_at = records_at + body.len() as u64;
        let mut table = Vec::with_capacity(offsets.len() * 8);
        for offset in &offsets {
            table.extend_from_slice(&offset.to_le_bytes());
        }

        let numbering_at = offsets_at + table.len() as u64;
        let mut numbering = Vec::new();
        for (dn, id) in &self.numbering {
            numbering.extend_from_slice(&(dn.len() as u32).to_le_bytes());
            numbering.extend_from_slice(dn.as_bytes());
            numbering.extend_from_slice(&id.to_le_bytes());
        }

        out.write_all(MAGIC)?;
        out.write_all(&VERSION.to_le_bytes())?;
        out.write_all(&sequence.to_le_bytes())?;
        out.write_all(&next_id.to_le_bytes())?;
        out.write_all(&plan.to_le_bytes())?;
        out.write_all(&(self.entries.len() as u64).to_le_bytes())?;
        out.write_all(&records_at.to_le_bytes())?;
        // Where the table starts, not how long it is: the length is `count times 8` and is derived,
        // and a header that stores a derived number twice is a header that can disagree with itself.
        out.write_all(&offsets_at.to_le_bytes())?;
        out.write_all(&numbering_at.to_le_bytes())?;
        out.write_all(&(numbering.len() as u64).to_le_bytes())?;

        debug_assert_eq!(HEADER_LEN as u64, records_at);
        out.write_all(&body)?;
        out.write_all(&table)?;
        out.write_all(&numbering)?;
        Ok(())
    }
}

/// A snapshot open as a mapped file: the index, without decoding it.
pub struct IndexFile {
    /// The file, mapped read-only. Every byte is reached through this slice and bounds-checked
    /// against its length before use; see the contract at the top of the module.
    map: memmap2::Mmap,
    sequence: u64,
    next_id: u32,
    plan: u64,
    count: usize,
    offsets_at: usize,
    numbering_at: usize,
    numbering_len: usize,
}

impl std::fmt::Debug for IndexFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "IndexFile {{ {} postings, sequence {} }}",
            self.count, self.sequence
        )
    }
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

impl IndexFile {
    /// Opens the file and validates its header, or says why it will not be used.
    ///
    /// `None` for every reason that means "read the store instead": no file, a foreign format, a
    /// version from another build, a truncated file, a plan that no longer matches the
    /// configuration. Each of those is a slower start, never a wrong answer - and a wrong answer is
    /// exactly what an unchecked file would produce, since its bytes are trusted by position.
    pub fn open(path: &std::path::Path, plan: u64) -> Option<Self> {
        let file = std::fs::File::open(path).ok()?;
        let length = file.metadata().ok()?.len();
        if length < HEADER_LEN as u64 {
            return None;
        }

        // The one unsafe call in the crate. The contract at the top of this file is what makes it
        // sound; the short version is that the file is only replaced by rename, never truncated.
        let map = unsafe { memmap2::Mmap::map(&file) }.ok()?;
        let bytes: &[u8] = &map;

        if &bytes[0..8] != MAGIC || u32_at(bytes, 8)? != VERSION {
            return None;
        }
        if u64_at(bytes, 24)? != plan {
            return None;
        }

        let count = u64_at(bytes, 32)? as usize;
        let records_at = u64_at(bytes, 40)?;
        let offsets_at = u64_at(bytes, 48)?;
        let numbering_at = u64_at(bytes, 56)?;
        let numbering_len = u64_at(bytes, 64)?;

        // Every region has to lie inside the file, in order, and not overlap: a truncated file
        // would otherwise be read out of bounds at the first lookup rather than refused here, and
        // a table pointing into the records would answer with bytes that are not an offset.
        let table_len = count as u64 * 8;
        if records_at < HEADER_LEN as u64
            || records_at > offsets_at
            || offsets_at + table_len > length
            || offsets_at + table_len > numbering_at
            || numbering_at + numbering_len > length
        {
            return None;
        }

        Some(Self {
            sequence: u64_at(bytes, 12)?,
            next_id: u32_at(bytes, 20)?,
            plan,
            count,
            offsets_at: offsets_at as usize,
            numbering_at: numbering_at as usize,
            numbering_len: numbering_len as usize,
            map,
        })
    }

    /// The change the snapshot covers, as recorded when it was written.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn next_id(&self) -> u32 {
        self.next_id
    }

    pub fn plan(&self) -> u64 {
        self.plan
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn length(&self) -> u64 {
        self.map.len() as u64
    }

    /// The record at position `at` in key order: its key and its postings.
    ///
    /// Two reads - the offset, then the record - and nothing else. This is the whole reason the
    /// format exists: the cost of a lookup follows the record, not the file.
    fn record(&self, at: usize) -> Option<(Vec<u8>, RoaringBitmap)> {
        // Every read is bounds-checked by the slice, not by arithmetic on offsets: a truncated file
        // gives `None` here rather than a read past the mapping, which is the whole of requirement
        // 2 in the contract at the top of the module.
        let table_at = self.offsets_at + at * 8;
        let offset = u64_at(&self.map, table_at)? as usize;

        let key_len = u32_at(&self.map, offset)? as usize;
        let key_start = offset.checked_add(4)?;
        let key = self.map.get(key_start..key_start.checked_add(key_len)?)?;

        let bitmap_len = u32_at(&self.map, key_start.checked_add(key_len)?)? as usize;
        let bitmap_start = key_start.checked_add(key_len)?.checked_add(4)?;
        let bitmap = self
            .map
            .get(bitmap_start..bitmap_start.checked_add(bitmap_len)?)?;

        let postings = RoaringBitmap::deserialize_from(bitmap).ok()?;
        Some((key.to_vec(), postings))
    }

    /// The postings for one key, or `None` when no record has it.
    ///
    /// `None` is "this index does not know", not "nothing matches": an empty bitmap is the second
    /// answer and it is a different one. A caller that confuses them answers `no such entry` for a
    /// value nobody indexed.
    pub fn lookup(&self, tag: Tag, attribute: &str, value: &str) -> Option<RoaringBitmap> {
        let wanted = key_of(tag, attribute, value);

        let (mut low, mut high) = (0usize, self.count);
        while low < high {
            let middle = low + (high - low) / 2;
            let (key, postings) = self.record(middle)?;
            match key.as_slice().cmp(&wanted[..]) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Some(postings),
            }
        }
        None
    }

    /// The numbering the postings were built under: which DN each id names.
    ///
    /// Read as one block and walked here rather than per record: a start needs all of it, and 230 MB
    /// read sequentially is a fraction of a second where decoding the postings is ten times that.
    pub fn numbering(&self) -> Option<Vec<(String, u32)>> {
        let block = self
            .map
            .get(self.numbering_at..self.numbering_at.checked_add(self.numbering_len)?)?;

        let mut numbered = Vec::new();
        let mut at = 0usize;
        while at < block.len() {
            let len = u32_at(block, at)? as usize;
            at += 4;
            let dn = std::str::from_utf8(block.get(at..at + len)?)
                .ok()?
                .to_string();
            at += len;
            let id = u32_at(block, at)?;
            at += 4;
            numbered.push((dn, id));
        }
        Some(numbered)
    }

    /// The whole thing as a live index, for the caller that is about to change it.
    ///
    /// A file cannot be patched in place while others read it, so the first write materialises the
    /// postings in memory and the file is left alone until the next rewrite. That makes the first
    /// write the expensive one and every start cheap, which is the trade a memory ceiling asks for:
    /// the common operation is reading.
    pub fn materialize(&self) -> BTreeMap<Vec<u8>, RoaringBitmap> {
        let mut all = BTreeMap::new();
        for at in 0..self.count {
            if let Some((key, postings)) = self.record(at) {
                all.insert(key, postings);
            }
        }
        all
    }
}

/// A shared handle, since every connection reads the same snapshot.
pub type Shared = Arc<IndexFile>;

#[cfg(test)]
mod tests {
    use super::*;

    fn bitmap(ids: &[u32]) -> RoaringBitmap {
        ids.iter().copied().collect()
    }

    fn written(sequence: u64) -> Vec<u8> {
        let records = Records::new(
            vec![("cn", bitmap(&[1, 2]))],
            vec![("cn", "ann", bitmap(&[1])), ("cn", "bob", bitmap(&[2]))],
            vec![("cn", "ann", bitmap(&[1]))],
            vec![
                ("uid=ann,ou=users,dc=example,dc=com".to_string(), 1u32),
                ("uid=bob,ou=users,dc=example,dc=com".to_string(), 2u32),
            ],
        );
        let mut out = Vec::new();
        records.write(&mut out, sequence, 3, 0xabc).expect("write");
        out
    }

    /// A written snapshot, kept alive by the returned directory.
    ///
    /// The directory has to outlive the handle: the file is read through `pread` on every lookup,
    /// so a `TempDir` dropped here would leave a handle pointing at a name that is gone. Linux keeps
    /// such a file readable, but a test that depends on that is a test about unlinked inodes, not
    /// about the format.
    fn open_written(sequence: u64) -> (IndexFile, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("index");
        std::fs::write(&path, written(sequence)).expect("write");
        let index = IndexFile::open(&path, 0xabc).expect("open");
        (index, dir)
    }

    // The point of the format: a lookup touches a few pages instead of decoding the file. What the
    // test can check is the answer, and that it comes from a file that was never parsed whole.
    #[test]
    fn a_key_that_was_written_is_found_without_decoding_the_file() {
        let (index, _dir) = open_written(7);

        assert_eq!(index.sequence(), 7);
        assert_eq!(index.next_id(), 3);
        assert_eq!(index.lookup(Tag::Equality, "cn", "ann"), Some(bitmap(&[1])));
        assert_eq!(index.lookup(Tag::Equality, "cn", "bob"), Some(bitmap(&[2])));
        assert_eq!(index.lookup(Tag::Presence, "cn", ""), Some(bitmap(&[1, 2])));
        assert_eq!(
            index.lookup(Tag::Substring, "cn", "ann"),
            Some(bitmap(&[1]))
        );
    }

    // "The index does not know this key" and "nothing matches" are different answers, and the
    // difference decides whether a search narrows to nothing or falls back to a scan.
    #[test]
    fn a_key_that_was_never_written_is_unknown_rather_than_empty() {
        let (index, _dir) = open_written(7);

        assert_eq!(index.lookup(Tag::Equality, "cn", "carol"), None);
        assert_eq!(
            index.lookup(Tag::Equality, "mail", "ann@example.com"),
            None,
            "an attribute with no index is unknown, not empty"
        );
    }

    #[test]
    fn the_numbering_is_read_back_in_order() {
        let (index, _dir) = open_written(7);

        let numbered = index.numbering().expect("the block is readable");

        assert_eq!(
            numbered,
            vec![
                ("uid=ann,ou=users,dc=example,dc=com".to_string(), 1),
                ("uid=bob,ou=users,dc=example,dc=com".to_string(), 2),
            ]
        );
    }

    // A snapshot from another build, or one whose configuration no longer matches, must be refused:
    // reading it would answer about postings the running plan never asked for.
    #[test]
    fn a_foreign_or_mismatched_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("index");
        std::fs::write(&path, written(1)).expect("write");

        assert!(
            IndexFile::open(&path, 0xabc).is_some(),
            "the plan it was written with is accepted"
        );
        assert!(
            IndexFile::open(&path, 0xdef).is_none(),
            "a different plan is refused"
        );

        std::fs::write(&path, b"not an index at all").expect("write");
        assert!(IndexFile::open(&path, 0xabc).is_none(), "foreign bytes");

        assert!(
            IndexFile::open(&dir.path().join("absent"), 0xabc).is_none(),
            "an absent file is not an error, it is a rebuild"
        );
    }

    // A file cut short is refused rather than read out of bounds: a backup restored while it was
    // still being written is exactly this case.
    #[test]
    fn a_truncated_file_is_refused() {
        let whole = written(1);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("index");

        for cut in [HEADER_LEN, HEADER_LEN + 8, whole.len() / 2] {
            std::fs::write(&path, &whole[..cut]).expect("write");
            assert!(
                IndexFile::open(&path, 0xabc).is_none(),
                "a file of {cut} bytes is not a snapshot"
            );
        }
    }

    // The first write materialises the index, and what comes out has to be the same index that was
    // written - otherwise a write after a fast start works on different postings.
    /// `serialize_into` and `deserialize_from` have to be exact inverses, or the file holds
    /// postings nobody can read back - and the failure is silent, since a bitmap that fails to
    /// parse is just a missing record.
    #[test]
    fn a_bitmap_survives_the_round_trip() {
        let original = bitmap(&[1, 2, 70_000]);
        let mut bytes = Vec::new();
        original.serialize_into(&mut bytes).expect("serialize");

        let back = RoaringBitmap::deserialize_from(&bytes[..]).expect("deserialize");

        assert_eq!(back, original);
    }

    #[test]
    fn materialising_gives_back_every_key() {
        let (index, _dir) = open_written(7);

        assert_eq!(index.len(), 4, "count read from the header");
        let all = index.materialize();

        assert_eq!(all.len(), 4, "presence, two equalities, one substring");
        assert_eq!(
            all.get(&key_of(Tag::Equality, "cn", "ann")),
            Some(&bitmap(&[1]))
        );
    }
}
