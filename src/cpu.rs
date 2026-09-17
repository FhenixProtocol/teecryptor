//! Bounded CPU execution gate.
//!
//! tfhe decryption is CPU-bound and single-threaded (verified against tfhe
//! 1.5.1: `integer/client_key` decrypts blocks with `blocks.iter()`, no rayon).
//! Running it inline on the async runtime lets a burst of decrypts starve the
//! accept loop and the outbound I/O tasks; running it on an *unbounded* blocking
//! pool oversubscribes the cores. [`run_gated`] does both right: it moves the
//! work onto tokio's blocking pool via `spawn_blocking`, bounded to a fixed
//! concurrency by a wait-only semaphore. Excess callers wait (FIFO-fair); none
//! are rejected.

use std::sync::Arc;

use tokio::sync::Semaphore;

/// Run CPU-bound `f` on the blocking pool, bounded by `gate`'s permits.
///
/// Acquires one permit (waiting if all are held — **never rejects**), then runs
/// `f` on a dedicated blocking thread. The permit is held *inside* the blocking
/// task, so it is released only when `f` actually finishes — not when the
/// caller's future is dropped (e.g. on client disconnect). That makes the gate a
/// hard concurrency cap even under a cancellation storm.
///
/// The returned [`tokio::task::JoinError`] only occurs if `f` panics.
pub async fn run_gated<F, R>(gate: &Arc<Semaphore>, f: F) -> Result<R, tokio::task::JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    // Acquire FIRST, on the async task — cheap, spawns no thread. If all permits
    // are held the caller is suspended here (a parked future, ~no CPU) until one
    // frees. `acquire_owned` only errors on a closed semaphore, which never
    // happens (we hold the `Arc` for the process lifetime).
    let permit = gate
        .clone()
        .acquire_owned()
        .await
        .expect("decrypt gate semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        // Permit rides along with the work and drops when `f` returns, so the
        // slot is freed only after the CPU work truly completes.
        let _permit = permit;
        f()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn never_exceeds_permits() {
        const N: usize = 3;
        const M: usize = 30;
        let gate = Arc::new(Semaphore::new(N));
        let cur = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..M {
            let (gate, cur, max) = (gate.clone(), cur.clone(), max.clone());
            handles.push(tokio::spawn(async move {
                run_gated(&gate, move || {
                    let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                    max.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(20));
                    cur.fetch_sub(1, Ordering::SeqCst);
                })
                .await
                .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            max.load(Ordering::SeqCst) <= N,
            "observed concurrency {} exceeded N={N}",
            max.load(Ordering::SeqCst),
        );
        assert_eq!(cur.load(Ordering::SeqCst), 0, "permit leak");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn all_tasks_complete_none_rejected() {
        const N: usize = 2;
        const M: usize = 20;
        let gate = Arc::new(Semaphore::new(N));
        let mut handles = Vec::new();
        for i in 0..M {
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                run_gated(&gate, move || i * 2).await.unwrap()
            }));
        }
        let mut got = Vec::new();
        for h in handles {
            got.push(h.await.unwrap());
        }
        got.sort_unstable();
        assert_eq!(got, (0..M).map(|i| i * 2).collect::<Vec<_>>());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panic_surfaces_as_join_error_without_poisoning() {
        let gate = Arc::new(Semaphore::new(1));
        let err = run_gated::<_, ()>(&gate, || panic!("boom")).await;
        assert!(err.is_err(), "panic should surface as JoinError");
        // The permit was released on the error path; the gate is still usable.
        let ok = run_gated(&gate, || 42).await.unwrap();
        assert_eq!(ok, 42);
    }
}
