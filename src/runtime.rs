//! The runtime this server runs on.
//!
//! Tokio names its threads `tokio-rt-worker` unless told otherwise, and that name is what `ps -L`,
//! `top -H` and a profiler show. On a machine that runs several services the default says nothing:
//! a thread burning a core could belong to this server or to any other tokio process, and the
//! answer costs an inspection of `/proc` that the name would have given for free.
//!
//! `#[tokio::main]` has no way to pass a name - the attribute only forwards the flavour, the worker
//! count and a couple of switches - so the runtime is built here explicitly.

/// The name every thread of the runtime carries.
///
/// Linux keeps 15 bytes of a thread name (`TASK_COMM_LEN` is 16 including the terminator), so a
/// longer string would be silently truncated and the check below would compare against something
/// the kernel never stored.
pub const THREAD_NAME: &str = "ldap-rt";

/// A multi-threaded runtime whose threads are named after this program.
///
/// Both the worker threads and the blocking pool take the name: tokio hands the same
/// `thread_name` to the pool it uses for file and CPU work, so a thread stuck in a blocking call
/// is attributable as well.
pub fn multi_thread() -> tokio::runtime::Runtime {
    assert!(
        THREAD_NAME.len() <= MAX_COMM_LEN,
        "a thread name longer than {MAX_COMM_LEN} bytes is truncated by the kernel"
    );

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name(THREAD_NAME)
        .build()
        .expect("a multi-threaded runtime")
}

/// What Linux stores from a thread name: `TASK_COMM_LEN` minus the terminator.
pub const MAX_COMM_LEN: usize = 15;

#[cfg(test)]
mod tests {
    use super::*;

    fn thread_names() -> Vec<String> {
        let mut names = Vec::new();
        let tasks = std::fs::read_dir("/proc/self/task").expect("the task directory");
        for task in tasks.flatten() {
            if let Ok(name) = std::fs::read_to_string(task.path().join("comm")) {
                names.push(name.trim_end().to_string());
            }
        }
        names
    }

    #[test]
    fn the_name_fits_what_the_kernel_keeps() {
        assert!(
            THREAD_NAME.len() <= MAX_COMM_LEN,
            "{THREAD_NAME} is {} bytes, and the kernel keeps {MAX_COMM_LEN}",
            THREAD_NAME.len()
        );
    }

    #[test]
    fn a_task_runs_on_a_thread_that_carries_the_name() {
        // The point of the rename is what an operator sees from outside, so the assertion reads the
        // kernel's own view - /proc/self/task/<tid>/comm - rather than trusting the builder's
        // argument. The task runs on a worker thread, so its own name must be among those listed.
        let runtime = multi_thread();
        let seen = runtime.block_on(async {
            tokio::spawn(async { thread_names() })
                .await
                .expect("the task")
        });
        runtime.shutdown_background();

        assert!(
            seen.iter().any(|name| name == THREAD_NAME),
            "no thread is called {THREAD_NAME}: {seen:?}"
        );
    }

    #[test]
    fn a_blocking_task_is_named_too() {
        // Separate from the worker threads: the blocking pool is what holds a thread while it reads
        // a file, and an unattributed thread there is the one most likely to be asked about.
        let runtime = multi_thread();
        let seen = runtime.block_on(async { tokio::task::spawn_blocking(thread_names).await });
        runtime.shutdown_background();

        let seen = seen.expect("the blocking task");
        assert!(
            seen.iter().filter(|name| *name == THREAD_NAME).count() >= 2,
            "the blocking pool thread is not named: {seen:?}"
        );
    }
}
