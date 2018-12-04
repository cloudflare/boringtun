use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

/// A special type of read/write lock, that makes the following assumptions:
/// a) Read access is frequent, and has to be very fast
/// b) Write access is very rare (think less than once per second) and can be a bit slower
/// c) A thread that holds a read lock, can ask for an upgrade to a write lock
pub struct Lock<T: ?Sized> {
    lock: AtomicUsize,
    data: UnsafeCell<T>,
}

#[derive(Debug)]
pub struct LockReadGuard<'a, T: 'a + ?Sized> {
    lock: &'a AtomicUsize,
    data: &'a mut T,
}

#[derive(Debug)]
pub struct UpgradableReadGuard<'a, T: 'a + ?Sized> {
    lock: &'a AtomicUsize,
    data: &'a mut T,
}

#[derive(Debug)]
pub struct LockWriteGuard<'a, T: 'a + ?Sized> {
    lock: &'a AtomicUsize,
    data: &'a mut T,
}

unsafe impl<T: ?Sized + Send> Send for Lock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for Lock<T> {}

// The MSB marks the intent to write lock, or the presence of a write lock
const MSB_MASK: usize = !(std::usize::MAX >> 1);

impl<T> Lock<T> {
    /// New lock
    pub const fn new(user_data: T) -> Lock<T> {
        Lock {
            lock: ATOMIC_USIZE_INIT,
            data: UnsafeCell::new(user_data),
        }
    }
}

impl<T: ?Sized> Lock<T> {
    /// Aquire a read lock
    pub fn read<'a>(&'a self) -> LockReadGuard<'a, T> {
        loop {
            let try_lock = self.lock.fetch_add(1, Ordering::SeqCst); // Increment readers counter optimistically
            if try_lock < MSB_MASK {
                return LockReadGuard {
                    lock: &self.lock,
                    data: unsafe { &mut *self.data.get() },
                };
            }

            // We have a writer waiting or in progress
            self.lock.fetch_sub(1, Ordering::Relaxed);

            // We actively yield the thread until the write lock is done
            while self.lock.load(Ordering::Relaxed) > MSB_MASK {
                std::thread::yield_now()
            }
        }
    }
}

impl<'a, T: ?Sized> LockReadGuard<'a, T> {
    /// Notify of an intent to upgrade the lock to a write lock
    /// Returns None if another thread wants to write, or performs a write
    pub fn mark_want_write<'b>(&'b mut self) -> Option<UpgradableReadGuard<'b, T>> {
        // We mark for write, by setting the MSB
        let try_mark = self.lock.fetch_or(MSB_MASK, Ordering::SeqCst);
        if try_mark < MSB_MASK {
            // If wasn't already set, return an upgradable lock
            Some(UpgradableReadGuard {
                lock: self.lock,
                data: self.data,
            })
        } else {
            None
        }
    }
}

impl<'a, T: ?Sized> UpgradableReadGuard<'a, T> {
    /// Aquire a write lock
    pub fn write<'b>(&'b mut self) -> LockWriteGuard<'b, T> {
        while self.lock.load(Ordering::SeqCst) != (MSB_MASK + 1) {
            // Because we already hold the read lock, wait until count drops to 1, this is essentially a spinlock
            std::sync::atomic::spin_loop_hint()
        }
        LockWriteGuard {
            lock: self.lock,
            data: self.data,
        }
    }
}

impl<'a, T: ?Sized> Deref for LockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: ?Sized> Deref for UpgradableReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: ?Sized> Deref for LockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: ?Sized> DerefMut for LockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

impl<'a, T: ?Sized> Drop for LockReadGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<'a, T: ?Sized> Drop for UpgradableReadGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.fetch_and(!MSB_MASK, Ordering::SeqCst);
    }
}
