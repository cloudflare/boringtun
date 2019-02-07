use super::{errno_str, Error};
use libc::*;
use spin::Mutex;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
use std::time::Duration;

/// Each file descriptor can be registered as an event with an event queue
pub struct EventFactory<H: Sized> {
    events: Mutex<Vec<Option<*mut Event<H>>>>,
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
    event: epoll_event, // The epoll event desctiption
    fd: RawFd,          // The associated fd
    queues: Vec<RawFd>, // The fds of all the queues it is registered with
    handler: H,         // The associated data
    once: bool,         // Remove after the first trigger
    notifier: bool,     // Is a notification event
    timer: bool,        // This is a pereodic event
}

impl<H> Drop for Event<H> {
    fn drop(&mut self) {
        // When the event is dropped we first remove it from every event queue in order to prevent future triggers
        for queue in self.queues.iter() {
            unsafe { epoll_ctl(*queue, EPOLL_CTL_DEL, self.fd, null_mut()) };
        }
    }
}

impl<H> Default for EventFactory<H> {
    fn default() -> Self {
        EventFactory {
            events: Mutex::new(vec![]),
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
        // The notifier on Linux uses the eventfd for notifications.
        // The way it works is when a non zero value is written into the eventfd it will trigger
        // the EPOLLIN event. Since we use it as a not ONESHOT it will keep triggering until
        // canceled.
        // When we want to stop the event, we read once from the file descriptor.something
        let efd = match unsafe { eventfd(0, EFD_NONBLOCK) } {
            -1 => return Err(Error::EventQueue(errno_str())),
            efd @ _ => efd,
        };

        // TODO: avoid code duplication with new_event
        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN) as _,
                u64: 0,
            },
            fd: efd,
            queues: vec![],
            handler,
            once: false,
            notifier: true,
            timer: false,
        };

        // Get raw pointer to the event
        let raw_ev = Box::into_raw(Box::new(ev));
        // The event will point to itself
        unsafe { raw_ev.as_mut().unwrap().event.u64 = raw_ev as _ };
        // Now add the pointer to the event vector, this is a place from which we can delete the event
        self.insert_at(efd as _, raw_ev);
        Ok(EventRef {
            trigger: efd,
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
        }
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

        assert_eq!(
            events[index], None,
            "Did not properly dispose of previous event"
        );

        events[index] = Some(data);
    }

    /// Register a new event with the factory, if the trigger is closed the event becomes stale
    /// once indicates the event should be dropped immidiately after first occurance
    pub fn new_event(&self, trigger: RawFd, handler: H, once: bool) -> EventRef<H> {
        // First create an event descriptor
        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: 0,
            },
            fd: trigger,
            queues: vec![],
            handler,
            once,
            notifier: false,
            timer: false,
        };
        // Get raw pointer to the event
        let raw_ev = Box::into_raw(Box::new(ev));
        // The event will point to itself
        unsafe { raw_ev.as_mut().unwrap().event.u64 = raw_ev as _ };
        // Now add the pointer to the event vector, this is a place from which we can delete the event
        self.insert_at(trigger as _, raw_ev);
        EventRef {
            trigger,
            phantom_marker: PhantomData,
        }
    }

    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef<H>, Error> {
        // The periodic event on Linux uses the timerfd
        let tfd = match unsafe { timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK) } {
            -1 => return Err(Error::Timer(errno_str())),
            efd @ _ => efd,
        };

        let ts = timespec {
            tv_sec: period.as_secs() as _,
            tv_nsec: period.subsec_nanos() as _,
        };

        let spec = itimerspec {
            it_value: ts,
            it_interval: ts,
        };

        if unsafe { timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) } == -1 {
            unsafe { close(tfd) };
            return Err(Error::Timer(errno_str()));
        }

        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: 0,
            },
            fd: tfd,
            queues: vec![],
            handler,
            once: false,
            notifier: false,
            timer: true,
        };

        // Get raw pointer to the event
        let raw_ev = Box::into_raw(Box::new(ev));
        // The event will point to itself
        unsafe { raw_ev.as_mut().unwrap().event.u64 = raw_ev as _ };
        // Now add the pointer to the event vector, this is a place from which we can delete the event
        self.insert_at(tfd as _, raw_ev);

        Ok(EventRef {
            trigger: tfd,
            phantom_marker: PhantomData,
        })
    }

    /// A new waitable poll
    pub fn new_poll(&self) -> Result<EventPoll<H>, Error> {
        let epoll = match unsafe { epoll_create(1) } {
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
        let mut events = self.events.lock();
        let ev_ptr = events[event.trigger as usize].expect("Expected existing event");
        let ev_data = unsafe { ev_ptr.as_mut().unwrap() };
        ev_data.queues.push(epoll.epoll);

        if ev_data.once {
            // A once event will be dropped when its EventGuard is dropped
            events[event.trigger as usize] = None;
        }

        match unsafe { epoll_ctl(epoll.epoll, EPOLL_CTL_ADD, ev_data.fd, &mut ev_data.event) } {
            0 => Ok(()),
            -1 => Err(Error::EventQueue(errno_str())),
            _ => panic!("Unexpected return value from epoll_ctl"),
        }
    }

    pub fn trigger_notification(&self, notification_event: &EventRef<H>) {
        let events = self.events.lock();
        let ev_ptr = events[notification_event.trigger as usize].expect("Expected existing event");
        let ev_data = unsafe { ev_ptr.as_mut().unwrap() };
        if !ev_data.notifier {
            panic!("Can only trigger a notification event");
        }

        unsafe {
            write(
                notification_event.trigger,
                &(std::u64::MAX - 1).to_ne_bytes()[0] as *const u8 as _,
                8,
            )
        };
    }

    pub fn stop_notification(&self, notification_event: &EventRef<H>) {
        let events = self.events.lock();
        let ev_ptr = events[notification_event.trigger as usize].expect("Expected existing event");
        let ev_data = unsafe { ev_ptr.as_mut().unwrap() };
        if !ev_data.notifier {
            panic!("Can only trigger a notification event");
        }

        let mut buf = [0u8; 8];
        unsafe {
            read(
                notification_event.trigger,
                &mut buf[0] as *mut u8 as _,
                buf.len() as _,
            )
        };
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
        let mut event = epoll_event { events: 0, u64: 0 };
        match unsafe { epoll_wait(self.epoll, &mut event, 1, -1) } {
            1 => {}
            -1 => return Err(Error::EventQueue(errno_str())),
            _ => panic!("Unexpected return value from epoll_wait"),
        }

        let event_data = unsafe { (event.u64 as *mut Event<H>).as_ref().unwrap() };
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
        if self.event.timer {
            // Must read from the timer before we enable it
            let mut buf = [0u8; 8];
            unsafe { read(self.event.fd, &mut buf[0] as *mut u8 as _, buf.len() as _) };
        }

        if self.event.once {
            // Remove a once event from epoll
            unsafe {
                epoll_ctl(
                    self.epoll,
                    EPOLL_CTL_DEL,
                    self.event.fd,
                    &mut self.event.event.clone(),
                );
            }
            // Drop the event
            unsafe { Box::from_raw(self.event.event.u64 as *mut Event<H>) };
        } else {
            unsafe {
                epoll_ctl(
                    self.epoll,
                    EPOLL_CTL_MOD,
                    self.event.fd,
                    &mut self.event.event.clone(),
                );
            }
        }
    }
}
