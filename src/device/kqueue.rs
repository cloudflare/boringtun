// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{errno_str, Error};
use libc::*;
use spin::Mutex;
use std::collections::HashMap;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::Duration;

/// A return type for the EventPoll::wait() function
pub enum WaitResult<'a, H> {
    /// Event triggered normally
    Ok(EventGuard<'a, H>),
    /// Event triggered due to End of File conditions
    EoF(EventGuard<'a, H>),
    /// There was an error
    Error(String),
}

struct Registry<H: Sized> {
    counter: u64,
    registry: HashMap<u64, Arc<Event<H>>>,
    by_fd: HashMap<RawFd, u64>,
}

/// Implements a registry of pollable events
pub struct EventPoll<H: Sized> {
    events: Mutex<Registry<H>>,
    kqueue: RawFd, // The OS kqueue
}

/// A type that hold a reference to a triggered Event
/// While an EventGuard exists for a given Event, it will not be triggered by any other thread
/// Once the EventGuard goes out of scope, the underlying Event will be re-enabled
pub struct EventGuard<'a, H> {
    kqueue: RawFd,
    id: u64,
    event: Arc<Event<H>>,
    poll: &'a EventPoll<H>,
}

/// A reference to a single event in an EventPoll
pub struct EventRef {
    trigger: u64,
}

#[derive(PartialEq, Clone)]
enum EventKind {
    FD,
    Notifier,
    Signal,
    Timer,
}

// A single event
struct Event<H> {
    event: kevent, // The kqueue event description
    handler: H,    // The associated data
    kind: EventKind,
}

impl<H> Drop for EventPoll<H> {
    fn drop(&mut self) {
        unsafe { close(self.kqueue) };
    }
}

unsafe impl<H> Send for EventPoll<H> {}
unsafe impl<H> Sync for EventPoll<H> {}

impl<H: Send + Sync> EventPoll<H> {
    /// Create a new event registry
    pub fn new() -> Result<EventPoll<H>, Error> {
        let kqueue = match unsafe { kqueue() } {
            -1 => return Err(Error::EventQueue(errno_str())),
            kqueue => kqueue,
        };

        Ok(EventPoll {
            events: Mutex::new(Registry {
                counter: 0,
                registry: HashMap::new(),
                by_fd: HashMap::new(),
            }),
            kqueue,
        })
    }

    /// Add and enable a new event with the factory.
    /// The event is triggered when a Read operation on the provided trigger becomes available
    /// If the trigger fd is closed, the event won't be triggered anymore, but it's data won't be
    /// automatically released.
    /// The safe way to delete an event, is using the cancel method of an EventGuard.
    /// If the same trigger is used with multiple events in the same EventPoll, the last added
    /// event overrides all previous events. In case the same trigger is used with multiple polls,
    /// each event will be triggered independently.
    /// The event will keep triggering until a Read operation is no longer possible on the trigger.
    /// When triggered, one of the threads waiting on the poll will receive the handler via an
    /// appropriate EventGuard. It is guaranteed that only a single thread can have a reference to
    /// the handler at any given time.
    pub fn new_event(&self, trigger: RawFd, handler: H) -> Result<EventRef, Error> {
        // Create an event descriptor
        let flags = EV_ENABLE | EV_DISPATCH;

        let ev = Event {
            event: kevent {
                ident: trigger as _,
                filter: EVFILT_READ,
                flags,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::FD,
        };

        self.register_event(ev)
    }

    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef, Error> {
        // The periodic event in BSD uses EVFILT_TIMER
        let ev = Event {
            event: kevent {
                ident: 0,
                filter: EVFILT_TIMER,
                flags: EV_ENABLE | EV_DISPATCH,
                fflags: NOTE_NSECONDS,
                data: period
                    .as_secs()
                    .checked_mul(1_000_000_000)
                    .unwrap()
                    .checked_add(u64::from(period.subsec_nanos()))
                    .unwrap() as _,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::Timer,
        };

        self.register_event(ev)
    }

    pub fn new_notifier(&self, handler: H) -> Result<EventRef, Error> {
        // The notifier in BSD uses EVFILT_USER for notifications.
        let ev = Event {
            event: kevent {
                ident: 0,
                filter: EVFILT_USER,
                flags: EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::Notifier,
        };

        self.register_event(ev)
    }

    /// Add and enable a new signal handler
    pub fn new_signal_event(&self, signal: c_int, handler: H) -> Result<EventRef, Error> {
        let ev = Event {
            event: kevent {
                ident: signal as _,
                filter: EVFILT_SIGNAL,
                flags: EV_ENABLE | EV_DISPATCH,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            handler,
            kind: EventKind::Signal,
        };

        self.register_event(ev)
    }

    /// Wait until one of the registered events becomes triggered. Once an event
    /// is triggered, a single caller thread gets the handler for that event.
    /// In case a notifier is triggered, all waiting threads will receive the same
    /// handler.
    pub fn wait(&'_ self) -> WaitResult<'_, H> {
        let mut event = kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: null_mut(),
        };

        if unsafe { kevent(self.kqueue, null(), 0, &mut event, 1, null()) } == -1 {
            return WaitResult::Error(errno_str());
        }
        let id = event.udata as u64;

        let event_data = {
            let events = self.events.lock();
            let event_data = events.registry.get(&id);
            if event_data.is_none() {
                return self.wait();
            }

            event_data.unwrap().clone()
        };

        let guard = EventGuard {
            kqueue: self.kqueue,
            id: id,
            event: event_data,
            poll: self,
        };

        if event.flags & EV_EOF != 0 {
            WaitResult::EoF(guard)
        } else {
            WaitResult::Ok(guard)
        }
    }

    // Register an event with this poll.
    fn register_event(&self, mut ev: Event<H>) -> Result<EventRef, Error> {
        let (kind, mut event) = {
            let mut events = self.events.lock();

            if ev.kind == EventKind::FD {
                // Check if there's already another event with this FD. Usually this means the FD was
                // closed and we weren't told about it.
                let fd = ev.event.ident as RawFd;
                if let Some(id) = events.by_fd.get(&fd) {
                    // Remove this event from the registry.
                    let id = *id;
                    events.registry.remove(&id);
                    events.by_fd.remove(&fd);
                }
            }

            // Get a unique id for this event and add it to the registry.
            let id = events.counter;
            events.counter += 1;

            ev.event.udata = id as _;
            if ev.kind == EventKind::Timer || ev.kind == EventKind::Notifier {
                ev.event.ident = id as usize;
            }

            let kind = ev.kind.clone();
            let event = ev.event.clone();

            if ev.kind == EventKind::FD {
                events.by_fd.insert(ev.event.ident as RawFd, id);
            }
            events.registry.insert(id, Arc::new(ev));

            (kind, event)
        };

        event.flags |= EV_ADD;

        if unsafe { kevent(self.kqueue, &event, 1, null_mut(), 0, null()) } == -1 {
            return Err(Error::EventQueue(errno_str()));
        }
        if kind == EventKind::Signal {
            // Mask the signal if successfully added to kqueue
            unsafe { signal(event.ident as RawFd, SIG_IGN) };
        }

        Ok(EventRef {
            trigger: event.udata as u64,
        })
    }

    pub fn trigger_notification(&self, notification_event: &EventRef) {
        let mut event = {
            let events = self.events.lock();
            let event_data = events
                .registry
                .get(&notification_event.trigger)
                .expect("Expected an event");
            if event_data.kind != EventKind::Notifier {
                panic!("Can only trigger a notification event");
            }

            event_data.event
        };

        event.fflags = NOTE_TRIGGER;

        unsafe { kevent(self.kqueue, &event, 1, null_mut(), 0, null()) };
    }

    pub fn stop_notification(&self, notification_event: &EventRef) {
        let mut event = {
            let events = self.events.lock();
            let event_data = events
                .registry
                .get(&notification_event.trigger)
                .expect("Expected an event");
            if event_data.kind != EventKind::Notifier {
                panic!("Can only stop a notification event");
            }

            event_data.event
        };

        event.flags = EV_DISABLE;
        event.fflags = 0;

        unsafe { kevent(self.kqueue, &event, 1, null_mut(), 0, null()) };
    }
}

impl<'a, H> Deref for EventGuard<'a, H> {
    type Target = H;
    fn deref(&self) -> &H {
        &self.event.handler
    }
}

impl<'a, H> Drop for EventGuard<'a, H> {
    fn drop(&mut self) {
        unsafe {
            // Re-enable the event once EventGuard goes out of scope
            kevent(self.kqueue, &self.event.event, 1, null_mut(), 0, null());
        }
    }
}

impl<'a, H> EventGuard<'a, H> {
    /// Cancel and remove the event represented by this guard
    pub fn cancel(self) {
        {
            let mut events = self.poll.events.lock();

            events.registry.remove(&self.id);
            if self.event.kind == EventKind::FD {
                let fd = self.event.event.ident as RawFd;
                if let Some(id) = events.by_fd.get(&fd) {
                    if *id == self.id {
                        events.by_fd.remove(&fd);
                    }
                }
            }
        };
        std::mem::forget(self); // Don't call the regular drop that would enable the event
    }
}
