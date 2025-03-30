use std::sync::Arc;

#[derive(Clone)]
pub struct WaitGroup {
    raw: Arc<RawWaitGroup>,
}

impl WaitGroup {
    /// Create a new semaphore around a resource.
    ///
    /// The semaphore will limit the number of processes that can access
    /// the underlying resource at every point in time to the specified capacity.
    pub fn new() -> Self {
        WaitGroup { raw: Arc::new(RawWaitGroup::new()) }
    }

    #[inline]
    /// Adds one to the wait group counter.
    ///
    /// Returns a WaitGroup guard that automatically decrements the wait group
    /// when the guard falls out of scope.
    pub fn add(&self) -> WaitGroupGuard {
        self.raw.add();
        WaitGroupGuard::new(&self.raw)
    }

    /// Waits until the wait group counter reaches 0.
    pub fn wait(&self) {
        self.raw.wait_until_inactive()
    }
}

/// RAII guard used to decrement the wait group counter automatically when it falls out of scope.
///
/// Returned from `WaitGroup::add`.
pub struct WaitGroupGuard {
    raw: Arc<RawWaitGroup>,
}

impl WaitGroupGuard {
    fn new(raw: &Arc<RawWaitGroup>) -> WaitGroupGuard {
        WaitGroupGuard { raw: raw.clone() }
    }
}

impl Drop for WaitGroupGuard {
    #[inline]
    fn drop(&mut self) {
        self.raw.release()
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::{Condvar, Mutex};

struct RawWaitGroup {
    active: AtomicUsize,
    lock: Mutex<()>,
    cond: Condvar,
}

impl RawWaitGroup {
    pub fn new() -> RawWaitGroup {
        RawWaitGroup {
            active: AtomicUsize::default(),
            lock: Mutex::new(()),
            cond: Condvar::new(),
        }
    }

    #[inline]
    pub fn add(&self) {
        loop {
            let current_active = self.active.load(Ordering::SeqCst);
            let Ok(previous_active) = self.active.compare_exchange(
                current_active,
                current_active + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) else {
                continue;
            };
            if previous_active == current_active {
                return;
            }
        }
    }

    #[inline]
    pub fn release(&self) {
        let previous_active = self.active.fetch_sub(1, Ordering::SeqCst);
        if previous_active == 1 {
            let _guard = self.lock.lock();
            self.cond.notify_all();
        }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst) > 0
    }

    #[inline]
    pub fn wait_until_inactive(&self) {
        let mut lock = self.lock.lock();

        while self.is_active() {
            self.cond.wait(&mut lock);
        }
    }
}
