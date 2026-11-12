//! Real heap numbers for the in-memory model, measured, not estimated.
//!
//! A counting allocator wraps the system one, so the numbers below are what the
//! process actually asked for while building a directory. This is the number the
//! storage layout has to justify itself against: 20 000 entries of six attributes
//! are a few megabytes of data, and an index has to be a fraction of that.
//!
//! Run: `./scripts/cargo.sh test --release --test memory -- --nocapture`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use rrl_directory::directory::Directory;
use rrl_directory::model::User;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live =
                LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed) + layout.size() as isize;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            let delta = new_size as isize - layout.size() as isize;
            let live = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The counter is process-wide, so the measurements must not overlap: without this
/// lock two test threads measure each other's allocations and the numbers (and the
/// assertions) become noise.
static MEASURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn measurement_guard() -> std::sync::MutexGuard<'static, ()> {
    MEASURE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn users(count: usize) -> Vec<User> {
    (0..count)
        .map(|index| User {
            object_class: vec![
                "top".to_string(),
                "posixAccount".to_string(),
                "inetOrgPerson".to_string(),
            ],
            cn: format!("user{index:05}"),
            uid: Some(format!("user{index:05}")),
            sn: Some(format!("Surname{index:05}")),
            mail: Some(format!("user{index:05}@example.com")),
            uid_number: Some(1000 + index as u32),
            gid_number: Some(2000),
            home_directory: Some(format!("/home/user{index:05}")),
            ..User::default()
        })
        .collect()
}

/// Measures the heap a directory holds, without the input data it was built from.
fn measure(count: usize) -> (isize, isize) {
    // Build the input outside the measured window, then free the baseline.
    let input = users(count);
    let before = LIVE.load(Ordering::Relaxed);

    let directory = Directory::new("dc=example,dc=com", "users", "groups", input, vec![]);
    let after = LIVE.load(Ordering::Relaxed);

    let entries = directory.len();
    assert_eq!(entries, count + 3);

    // Report, then release so the next measurement starts clean.
    let bytes = after - before;
    drop(directory);
    (bytes, PEAK.load(Ordering::Relaxed))
}

#[test]
fn heap_per_entry() {
    let _guard = measurement_guard();

    for count in [1_000usize, 20_000] {
        let (bytes, _peak) = measure(count);
        let per_entry = bytes as f64 / (count as f64 + 3.0);

        println!("entries {count:>6}: {bytes:>10} bytes total, {per_entry:>8.1} bytes per entry");

        assert!(
            per_entry < 3_000.0,
            "an entry must not cost more than a few kilobytes: {per_entry}"
        );
    }
}

#[test]
fn attribute_names_are_shared_between_entries() {
    // Six attributes per entry, 20 000 entries: if every name were its own
    // allocation this would dwarf the values. The test states the invariant the
    // layout relies on, and fails loudly if the sharing is lost.
    let _guard = measurement_guard();
    let (bytes, _peak) = measure(20_000);

    println!("20k entries: {bytes} bytes");
    assert!(
        bytes < 20_000 * 900,
        "20k entries must fit well under 18 MB, got {} bytes",
        bytes
    );
}
