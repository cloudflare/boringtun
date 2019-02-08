use super::{errno_str, Error};
use libc::*;
use spin::Mutex;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::{null, null_mut};
use std::time::Duration;

/// Each file descriptor can be registered as an event with an event queue
pub struct EventFactory<H: Sized> {
    events: Mutex<Vec<Option<*mut Event<H>>>>,
    custom: Mutex<Vec<Option<*mut Event<H>>>>, // timers + notifiers
}

unsafe impl<H> Send for EventFactory<H> {}
unsafe impl<H> Sync for EventFactory<H> {}

pub struct EventPoll<H> {
    epoll: RawFd,
    phantom_marker: PhantomData<H>,
}

#[derive(Clone, Copy)]
pub struct EventRef<H> {
    trigger: RawFd,
    phantom_marker: PhantomData<H>,
}

pub struct EventGuard<'a, H> {
    epoll: RawFd,
    event: &'a Event<H>,
}

struct Event<H> {
    event: kevent,      // The kqueue event desctiption
    queues: Vec<RawFd>, // The fds of all the queues it is registered with
    handler: H,         // The associated data
    once: bool,         // Remove after the first trigger
    notifier: bool,     // Is a notification event
}

impl<H> Drop for Event<H> {
    fn drop(&mut self) {
        // When the event is dropped we first remove it from every event queue in order to prevent future triggers
        for queue in self.queues.iter() {
            self.event.flags = EV_DELETE;
            unsafe { kevent(*queue, &self.event, 1, null_mut(), 0, null()) };
        }
    }
}

impl<H> Default for EventFactory<H> {
    fn default() -> Self {
        EventFactory {
            events: Mutex::new(vec![]),
            custom: Mutex::new(vec![]),
        }
    }
}

impl<H> Drop for EventFactory<H> {
    fn drop(&mut self) {
        let events = self.events.lock();
        for e in events.iter() {
            if let Some(event) = *e {
                unsafe { Box::from_raw(event) }; // Drop all the events
            }
        }
    }
}

impl<H> EventFactory<H>
where
    H: Sync + Send,
{
    pub fn new_notifier(&self, handler: H) -> Result<EventRef<H>, Error> {
        // The notifier on macOS uses EVFILT_USER for notifications.
        let ev = Event {
            event: kevent {
                ident: 0,
                filter: EVFILT_USER,
                flags: EV_ENABLE,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            queues: vec![],
            handler,
            once: false,
            notifier: true,
        };
        // Get raw pointer to the event
        let raw_ev = Box::into_raw(Box::new(ev));
        // The event will point to itself
        unsafe { raw_ev.as_mut().unwrap().event.udata = raw_ev as _ };
        // Now add the pointer to the event vector, this is a place from which we can delete the event
        let idx = self.insert_custom(raw_ev);
        unsafe { raw_ev.as_mut().unwrap().event.ident = idx };
        Ok(EventRef {
            trigger: -(idx as RawFd), // use negative numbers for custom events
            phantom_marker: PhantomData,
        })
    }
}

impl<H> EventFactory<H>
where
    H: Send,
{
    /// Create a new event factory
    pub fn new() -> EventFactory<H> {
        EventFactory {
            events: Mutex::new(vec![]),
            custom: Mutex::new(vec![]),
        }
    }

    fn insert_custom(&self, data: *mut Event<H>) -> usize {
        let mut events = self.custom.lock();
        events.push(Some(data));
        events.len()
    }

    fn insert_at(&self, index: usize, data: *mut Event<H>) {
        let mut events = self.events.lock();
        // Resize if needed
        let new_len = if events.len() < (index + 1) as usize {
            index + 1
        } else {
            events.len()
        };
        events.resize(new_len, None);

        // TODO: need to remove an event assosiated with a reused fd
        //assert_eq!(
        //    events[index], None,
        //    "Did not properly dispose of previous event"
        //);

        events[index] = Some(data);
    }

    /// Register a new event with the factory, if the trigger is closed the event becomes stale
    /// once indicates the event should be dropped immidiately after first occurance
    pub fn new_event(&self, trigger: RawFd, handler: H, once: bool) -> EventRef<H> {
        // First create an event descriptor
        let flags = if once {
            EV_ENABLE | EV_ONESHOT
        } else {
            EV_ENABLE | EV_DISPATCH
        };

        let ev = Event {
            event: kevent {
                ident: trigger as _,
                filter: EVFILT_READ,
                flags,
                fflags: 0,
                data: 0,
                udata: null_mut(),
            },
            queues: vec![],
            handler,
            once,
            notifier: false,
        };
        // Get raw pointer to the event
        let raw_ev = Box::into_raw(Box::new(ev));
        // The event will point to itself
        unsafe { raw_ev.as_mut().unwrap().event.udata = raw_ev as _ };
        // Now add the pointer to the event vector, this is a place from which we can delete the event
        self.insert_at(trigger as _, raw_ev);
        EventRef {
            trigger,
            phantom_marker: PhantomData,
        }
    }

    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef<H>, Error> {
        // The periodic event on macOS uses EVFILT_TIMER
        // The notifier on macOS uses EVFILT_USER for notifications.
        let ev = Event {
            event: kevent {
                ident: 0,
                filter: EVFILT_TIMER,
                flags: EV_ENABLE | EV_DISPATCH,
                fflags: NOTE_BACKGROUND | NOTE_NSECONDS,
                data: period
                    .as_secs()
                    .checked_mul(1_000_000_000)
                    .unwrap()
                    .checked_add(period.subsec_nanos() as _)
                    .unwrap() as _,
                udata: null_mut(),
            },
            queues: vec![],
            handler,
            once: false,
            notifier: false,
        };
        // Get raw pointer to the event
        let raw_ev = Box::into_raw(Box::new(ev));
        // The event will point to itself
        unsafe { raw_ev.as_mut().unwrap().event.udata = raw_ev as _ };
        // Now add the pointer to the event vector, this is a place from which we can delete the event
        let idx = self.insert_custom(raw_ev);
        unsafe { raw_ev.as_mut().unwrap().event.ident = idx };
        Ok(EventRef {
            trigger: -(idx as RawFd), // use negative numbers for custom events
            phantom_marker: PhantomData,
        })
    }

    /// A new waitable poll
    pub fn new_poll(&self) -> Result<EventPoll<H>, Error> {
        let epoll = match unsafe { kqueue() } {
            -1 => return Err(Error::EventQueue(errno_str())),
            epoll @ _ => epoll,
        };

        Ok(EventPoll {
            epoll,
            phantom_marker: PhantomData,
        })
    }

    /// Register a given event with a given poll
    pub fn register_event(&self, epoll: &EventPoll<H>, event: &EventRef<H>) -> Result<(), Error> {
        // get the event descriptor via pointer

        let (ev_index, events) = if event.trigger < 0 {
            (-event.trigger - 1, &self.custom)
        } else {
            (event.trigger, &self.events)
        };

        let mut events = events.lock();
        let ev_ptr = events[ev_index as usize].expect("Expected existing event");
        let ev_data = unsafe { ev_ptr.as_mut().unwrap() };
        ev_data.queues.push(epoll.epoll);

        if ev_data.once {
            // A once event will be dropped when its EventGuard is dropped
            events[event.trigger as usize] = None;
        }

        let mut kev = ev_data.event.clone();
        kev.flags |= EV_ADD;

        match unsafe { kevent(epoll.epoll, &kev, 1, null_mut(), 0, null()) } {
            0 => Ok(()),
            -1 => Err(Error::EventQueue(errno_str())),
            _ => panic!("Unexpected return value from epoll_ctl"),
        }
    }

    pub fn trigger_notification(&self, notification_event: &EventRef<H>) {
        let events = self.custom.lock();
        let ev_index = -notification_event.trigger - 1; // Custom events have negative index from -1
        let ev_ptr = events[ev_index as usize].expect("Expected existing event");
        let ev_data = unsafe { ev_ptr.as_mut().unwrap() };
        if !ev_data.notifier {
            panic!("Can only trigger a notification event");
        }

        let mut kev = ev_data.event.clone();
        kev.fflags = NOTE_TRIGGER;

        for queue in ev_data.queues.iter() {
            unsafe { kevent(*queue, &kev, 1, null_mut(), 0, null()) };
        }
    }

    pub fn stop_notification(&self, notification_event: &EventRef<H>) {
        let events = self.custom.lock();
        let ev_index = -notification_event.trigger - 1; // Custom events have negative index from -1
        let ev_ptr = events[ev_index as usize].expect("Expected existing event");
        let ev_data = unsafe { ev_ptr.as_mut().unwrap() };
        if !ev_data.notifier {
            panic!("Can only stop a notification event");
        }

        let mut kev = ev_data.event.clone();
        kev.flags = EV_DISABLE;
        kev.fflags = 0;

        for queue in ev_data.queues.iter() {
            unsafe { kevent(*queue, &kev, 1, null_mut(), 0, null()) };
        }
    }
}

impl<H> Default for EventPoll<H> {
    fn default() -> Self {
        EventPoll {
            epoll: -1,
            phantom_marker: PhantomData,
        }
    }
}

impl<H> EventPoll<H> {
    pub fn wait<'a>(&self) -> Result<EventGuard<'a, H>, Error> {
        let mut event = kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: null_mut(),
        };

        match unsafe { kevent(self.epoll, null(), 0, &mut event, 1, null()) } {
            1 => {}
            -1 => return Err(Error::EventQueue(errno_str())),
            _ => panic!("Unexpected return value from epoll_wait"),
        }

        let event_data = unsafe { (event.udata as *mut Event<H>).as_ref().unwrap() };

        if event.flags & EV_EOF != 0 {
            // On EOF we remove the event from the queue (for example socket shutdown)
            // TODO: let the caller control this case
            for queue in event_data.queues.iter() {
                event.flags = EV_DELETE;
                unsafe { kevent(*queue, &event, 1, null_mut(), 0, null()) };
            }
            // Drop
            unsafe { Box::from_raw(event.udata as *mut Event<H>) };
            return Err(Error::EventQueue("Event dropped (EOF)".to_owned()));
        }

        Ok(EventGuard {
            epoll: self.epoll,
            event: &event_data,
        })
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
        if self.event.once {
            // Drop
            unsafe { Box::from_raw(self.event.event.udata as *mut Event<H>) };
        } else {
            unsafe {
                kevent(self.epoll, &self.event.event, 1, null_mut(), 0, null());
            }
        }
    }
}
