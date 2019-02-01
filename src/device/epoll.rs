use super::{errno_str, Device, Error, HandlerFunction};
use dev_lock::*;
use device::peer::Peer;
use libc::*;
use std::os::unix::io::RawFd;
use std::sync::Arc;

pub trait Descriptor {
    fn descriptor(&self) -> RawFd;
}

// Linux wait
#[derive(Default)]
pub struct EventQueue {
    epoll: RawFd,
    efd: RawFd,
    timerfd: RawFd,
    timerfd_ev: Option<epoll_event>,
}

pub struct Event {
    event: epoll_event,
}

pub enum EventType {
    None,
    ConnectedPeer(Arc<Peer>),
}

pub struct EventData {
    fd: RawFd,
    handler: &'static HandlerFunction,
    handler_cl: Option<Box<Fn() -> Option<()>>>,
    pub extra: EventType,
}

impl Event {
    // Create a new event that can be registered with the queue
    pub fn new_event(trigger: RawFd, handler: &'static HandlerFunction, extra: EventType) -> Event {
        let udata = Box::into_raw(Box::new(EventData {
            fd: trigger,
            handler,
            handler_cl: None,
            extra,
        }));

        Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: udata as *mut EventData as _,
            },
        }
    }

    // Create a new event that can be registered with the queue
    pub fn new_event2(trigger: RawFd, handler: Box<Fn() -> Option<()>>) -> Event {
        let udata = Box::into_raw(Box::new(EventData {
            fd: trigger,
            handler: &super::CONNECTED_SOCKET_HANDLER,
            handler_cl: Some(handler),
            extra: EventType::None,
        }));

        Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: udata as *mut EventData as _,
            },
        }
    }

    // Create a new event that can be registered with the queue
    pub fn new_read_event<D>(
        trigger: &D,
        handler: &'static HandlerFunction,
        extra: EventType,
    ) -> Event
    where
        D: Descriptor,
    {
        let udata = Box::into_raw(Box::new(EventData {
            fd: trigger.descriptor(),
            handler_cl: None,
            handler,
            extra,
        }));

        Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT) as _,
                u64: udata as *mut EventData as _,
            },
        }
    }

    // Call the handler function for this event
    pub fn handle(self, device: &mut LockReadGuard<Device>) -> Option<()> {
        let udata = self.event.u64 as *const EventData;
        let fd = unsafe { (*udata).fd };
        let handler = unsafe { (*udata).handler };
        handler(fd, device, self)
    }

    pub fn data(&self) -> &EventData {
        unsafe { (self.event.u64 as *const EventData).as_ref().unwrap() }
    }
}

impl Drop for EventQueue {
    fn drop(&mut self) {
        unsafe { close(self.epoll) };
        unsafe { close(self.efd) };
        unsafe { close(self.timerfd) };
    }
}

impl Descriptor for EventQueue {
    fn descriptor(&self) -> RawFd {
        self.epoll
    }
}

impl EventQueue {
    pub fn new() -> Result<EventQueue, Error> {
        let epoll = match unsafe { epoll_create(1) } {
            -1 => return Err(Error::EventQueue(errno_str())),
            epoll @ _ => epoll,
        };

        let efd = match unsafe { eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK) } {
            -1 => return Err(Error::EventQueue(errno_str())),
            efd @ _ => efd,
        };

        let timerfd = match unsafe { timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK) } {
            -1 => return Err(Error::Timer(errno_str())),
            timerfd @ _ => timerfd,
        };

        Ok(EventQueue {
            epoll,
            efd,
            timerfd,
            timerfd_ev: None,
        })
    }

    pub fn register_event(&self, mut ev: Event) -> Result<(), Error> {
        match unsafe { epoll_ctl(self.epoll, EPOLL_CTL_ADD, ev.data().fd, &mut ev.event) } {
            0 => Ok(()),
            -1 => Err(Error::EventQueue(errno_str())),
            _ => panic!("Impossible return value"),
        }
    }

    pub fn enable_event(&self, mut ev: Event) -> Result<(), Error> {
        ev.event.events = (EPOLLIN | EPOLLONESHOT) as _;
        match unsafe { epoll_ctl(self.epoll, EPOLL_CTL_MOD, ev.data().fd, &mut ev.event) } {
            0 => Ok(()),
            -1 => Err(Error::EventQueue(errno_str())),
            _ => panic!("Impossible return value"),
        }
    }

    pub fn remove_event(&self, mut ev: Event) -> Result<(), Error> {
        // TODO: free user data
        match unsafe { epoll_ctl(self.epoll, EPOLL_CTL_DEL, ev.data().fd, &mut ev.event) } {
            0 => Ok(()),
            -1 => Err(Error::EventQueue(errno_str())),
            _ => panic!("Impossible return value"),
        }
    }

    pub fn wait(&self) -> Option<Event> {
        let mut event = epoll_event { events: 0, u64: 0 };
        match unsafe { epoll_wait(self.descriptor(), &mut event, 1, -1) } {
            1 => Some(Event { event }),
            -1 => None,
            _ => panic!("Unexpected result from epoll_wait"),
        }
    }

    pub fn trigger_notification(&self) {
        let udata = Box::into_raw(Box::new(EventData {
            fd: self.efd,
            handler: &super::COOP_HANDLER,
            handler_cl: None,
            extra: EventType::None,
        }));

        let mut ev = epoll_event {
            events: EPOLLIN as _,
            u64: udata as *mut EventData as _,
        };

        unsafe { epoll_ctl(self.epoll, EPOLL_CTL_ADD, self.efd, &mut ev) };

        unsafe {
            write(
                self.efd,
                &(std::u64::MAX - 1).to_ne_bytes()[0] as *const u8 as _,
                8,
            )
        };
    }

    pub fn stop_notification(&self) {
        unsafe { epoll_ctl(self.epoll, EPOLL_CTL_DEL, self.efd, std::ptr::null_mut()) };
    }

    pub fn start_timer(
        &mut self,
        period: std::time::Duration,
        handler: &'static HandlerFunction,
    ) -> Result<(), Error> {
        let ts = timespec {
            tv_sec: period.as_secs() as _,
            tv_nsec: period.subsec_nanos() as _,
        };

        let spec = itimerspec {
            it_value: ts,
            it_interval: ts,
        };

        if unsafe { timerfd_settime(self.timerfd, 0, &spec, std::ptr::null_mut()) } == -1 {
            return Err(Error::Timer(errno_str()));
        }

        let udata = Box::into_raw(Box::new(EventData {
            fd: self.timerfd,
            handler_cl: None,
            handler: handler,
            extra: EventType::None,
        }));

        let mut ev = epoll_event {
            events: (EPOLLIN | EPOLLONESHOT) as _,
            u64: udata as *mut EventData as _,
        };

        self.timerfd_ev = Some(ev.clone());

        unsafe { epoll_ctl(self.epoll, EPOLL_CTL_ADD, self.timerfd, &mut ev) };

        Ok(())
    }

    pub fn reset_timer(&self) {
        let mut buf = [0u8; 8];
        unsafe { read(self.timerfd, &mut buf[0] as *mut u8 as _, buf.len() as _) };
        let mut ev = self.timerfd_ev.unwrap().clone();
        unsafe { epoll_ctl(self.epoll, EPOLL_CTL_MOD, self.timerfd, &mut ev) };
    }
}
