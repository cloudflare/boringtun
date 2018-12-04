use super::{errno_str, Device, Error, HandlerFunction};
use dev_lock::*;
use device::peer::Peer;
use libc::*;
use std::os::unix::io::RawFd;
use std::sync::Arc;

pub trait Descriptor {
    fn descriptor(&self) -> RawFd;
}

// BSD kqueue
#[derive(Default)]
pub struct EventQueue {
    kq: RawFd,
    timer_ev: Option<kevent>,
}

unsafe impl Send for EventQueue {}
unsafe impl Sync for EventQueue {}

pub struct Event {
    event: kevent,
}

pub enum EventType {
    None,
    ConnectedPeer(Arc<Peer>),
}

pub struct EventData {
    handler: &'static HandlerFunction,
    pub extra: EventType,
}

impl Event {
    pub fn new_event(trigger: RawFd, handler: &'static HandlerFunction, extra: EventType) -> Event {
        let udata = Box::into_raw(Box::new(EventData { handler, extra }));

        Event {
            event: kevent {
                ident: trigger as _,
                filter: EVFILT_READ,
                flags: EV_ADD | EV_DISPATCH,
                fflags: 0,
                data: 0,
                udata: udata as *mut EventData as _,
            },
        }
    }

    pub fn new_read_event<D: Descriptor>(
        trigger: &D,
        handler: &'static HandlerFunction,
        extra: EventType,
    ) -> Event {
        let udata = Box::into_raw(Box::new(EventData { handler, extra }));

        Event {
            event: kevent {
                ident: trigger.descriptor() as _,
                filter: EVFILT_READ,
                flags: EV_ADD | EV_DISPATCH,
                fflags: 0,
                data: 0,
                udata: udata as *mut EventData as _,
            },
        }
    }

    pub fn handle(self, device: &mut LockReadGuard<Device>) -> Option<()> {
        let udata = self.event.udata as *const EventData;
        let fd = self.event.ident as RawFd;
        let handler = unsafe { (*udata).handler };
        handler(fd, device, self)
    }

    pub fn data(&self) -> &EventData {
        unsafe { (self.event.udata as *const EventData).as_ref().unwrap() }
    }
}

impl Drop for EventQueue {
    fn drop(&mut self) {
        unsafe { close(self.kq) };
    }
}

impl Descriptor for EventQueue {
    fn descriptor(&self) -> RawFd {
        self.kq
    }
}

impl EventQueue {
    pub fn new() -> Result<EventQueue, Error> {
        match unsafe { kqueue() } {
            -1 => Err(Error::EventQueue(errno_str())),
            kq @ _ => Ok(EventQueue { kq, timer_ev: None }),
        }
    }

    pub fn register_event(&self, ev: Event) -> Result<(), Error> {
        match unsafe {
            kevent(
                self.kq,
                &ev.event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } {
            0 => Ok(()),
            _ => Err(Error::EventQueue(errno_str())),
        }
    }

    pub fn enable_event(&self, mut ev: Event) -> Result<(), Error> {
        ev.event.flags = EV_ENABLE;
        match unsafe {
            kevent(
                self.kq,
                &ev.event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } {
            0 => Ok(()),
            _ => Err(Error::EventQueue(errno_str())),
        }
    }

    pub fn remove_event(&self, mut ev: Event) -> Result<(), Error> {
        ev.event.flags = EV_DELETE;
        match unsafe {
            kevent(
                self.kq,
                &ev.event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } {
            0 => Ok(()),
            _ => Err(Error::EventQueue(errno_str())),
        }
    }

    pub fn wait(&self) -> Option<Event> {
        let mut event = kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };

        match unsafe {
            kevent(
                self.descriptor(),
                std::ptr::null(),
                0,
                &mut event,
                1,
                std::ptr::null(),
            )
        } {
            1 => Some(Event { event }),
            _ => None,
        }
    }

    pub fn trigger_notification(&self) {
        let udata = Box::into_raw(Box::new(EventData {
            handler: &super::COOP_HANDLER,
            extra: EventType::None,
        }));

        let event = kevent {
            ident: 0,
            filter: EVFILT_USER,
            flags: EV_ADD,
            fflags: NOTE_TRIGGER,
            data: 0,
            udata: udata as *mut EventData as _,
        };

        unsafe {
            kevent(
                self.descriptor(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            );
        }
    }

    pub fn stop_notification(&self) {
        let udata = Box::into_raw(Box::new(EventData {
            handler: &super::COOP_HANDLER,
            extra: EventType::None,
        }));

        let event = kevent {
            ident: 0,
            filter: EVFILT_USER,
            flags: EV_DELETE,
            fflags: 0,
            data: 0,
            udata: udata as *mut EventData as _,
        };

        unsafe {
            kevent(
                self.descriptor(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            );
        }
    }

    pub fn start_timer(
        &mut self,
        period: std::time::Duration,
        handler: &'static HandlerFunction,
    ) -> Result<(), Error> {
        let udata = Box::into_raw(Box::new(EventData {
            handler,
            extra: EventType::None,
        }));

        let ev = kevent {
            ident: 1000,
            filter: EVFILT_TIMER,
            flags: EV_ADD | EV_ONESHOT,
            fflags: NOTE_BACKGROUND | NOTE_NSECONDS,
            data: period
                .as_secs()
                .checked_mul(1_000_000_000)
                .unwrap()
                .checked_add(period.subsec_nanos() as _)
                .unwrap() as _,
            udata: udata as *mut EventData as _,
        };

        self.timer_ev = Some(ev.clone());
        self.timer_ev.unwrap().flags = EV_ENABLE;

        match unsafe { kevent(self.kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) } {
            0 => Ok(()),
            _ => Err(Error::Timer(errno_str())),
        }
    }

    pub fn reset_timer(&self) {
        let ev = self.timer_ev.unwrap().clone();
        unsafe { kevent(self.kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    }
}
