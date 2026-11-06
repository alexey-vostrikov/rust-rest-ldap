//! How much memory this process is holding, and what to say when it is too much.
//!
//! The number comes from the kernel rather than from a counter of our own. A counter would count
//! what we believe we allocated, which is not what decides whether the machine starts swapping:
//! allocator slack, page-cache-friendly copies and the runtime's own arenas all live outside it.
//! `/proc/self/statm` is two integers per read and needs no privileges.
//!
//! What this is *not*: a limiter. Refusing to allocate once a ceiling is reached would turn a
//! memory surprise into an outage, and the operator who set the ceiling would find out by the
//! service disappearing. The ceiling is a statement of intent that the server reports against -
//! loud when exceeded, never fatal - because a server that is up and slow beats one that is down
//! and correct about why.

/// Resident set size of this process, in bytes.
///
/// `None` where `/proc` is absent or unreadable (not Linux). Absent is not zero: a caller must be
/// able to tell "this platform does not report" from "no memory in use", or a report against a
/// ceiling would be a false all-clear.
pub fn resident_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    // "size resident shared ..." in pages. Resident is the second field; the rest are not needed.
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(page_size()))
}

/// The page size, which the kernel tells us rather than us assuming four kilobytes.
fn page_size() -> u64 {
    // `getconf PAGE_SIZE` says 4096 on every platform this runs on today, but reading it beats
    // assuming it: on a 64 KiB-page system the assumption is wrong by sixteen times, and the
    // number is used to decide whether a directory fits.
    std::fs::read_to_string("/proc/self/smaps_rollup")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("KernelPageSize:")
                    .and_then(|value| value.trim().strip_suffix(" kB"))
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map(|kib| kib * 1024)
            })
        })
        .unwrap_or(4096)
}

/// A report against a ceiling, for the one log line an operator reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub resident: u64,
    pub ceiling: u64,
}

impl Usage {
    /// Reads the process and compares it with the ceiling, or `None` when the platform does not
    /// report resident memory.
    pub fn against(ceiling: u64) -> Option<Self> {
        resident_bytes().map(|resident| Self { resident, ceiling })
    }

    pub fn exceeded(&self) -> bool {
        self.resident > self.ceiling
    }

    /// Bytes over the ceiling; zero when under it.
    pub fn excess(&self) -> u64 {
        self.resident.saturating_sub(self.ceiling)
    }
}

impl std::fmt::Display for Usage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} in use, {} allowed",
            crate::limits::Size(self.resident),
            crate::limits::Size(self.ceiling)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The reader has to answer on the platform it runs on, and it has to answer something
    // plausible: a process holding nothing reports nothing, and a running one reports more.
    #[test]
    fn the_reader_answers_a_plausible_number() {
        let Some(bytes) = resident_bytes() else {
            // Not Linux: the contract is `None`, and a test cannot demand more than that.
            return;
        };

        assert!(
            bytes > 1024 * 1024,
            "a running test binary holds at least a megabyte, got {bytes}"
        );
    }

    #[test]
    fn a_ceiling_below_what_is_used_is_reported_as_exceeded() {
        let usage = Usage::against(1024).expect("this platform reports memory");

        assert!(usage.exceeded(), "{usage}");
        // Read from the usage itself: the process grows between two reads, and a test that
        // compares two independent samples is a test that fails for the wrong reason.
        assert_eq!(usage.excess(), usage.resident - 1024);
    }

    #[test]
    fn a_ceiling_above_what_is_used_is_not_exceeded_and_has_no_excess() {
        let usage = Usage::against(u64::MAX).expect("reported");

        assert!(!usage.exceeded(), "{usage}");
        assert_eq!(usage.excess(), 0);
    }
}
