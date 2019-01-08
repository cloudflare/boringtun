use noise::{result_type, wireguard_result, Tunn, Verbosity};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

/*
static MAX_TIMER_HANDSHAKES: u32 = 90 / 5;
static COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);
static HANDSHAKE_INITATION_RATE: Duration = Duration::from_millis(50);
*/

// Some constants, represent time in seconds
const KEEPALIVE_TIMEOUT: usize = 10;
const REKEY_TIMEOUT: usize = 5;
const REKEY_AFTER_TIME: usize = 90;
const REJECT_AFTER_TIME: usize = 180;
const REKEY_ATTEMPT_TIME: usize = 90;
const COOKIE_EXPIRATION_TIME: usize = 120;

pub enum TimerName {
    TimeCurrent,
    TimeSessionEstablished,
    TimeLastHandshakeStarted,
    TimeLastPacketReceived,
    TimeLastPacketSent,
    TimeCookieReceived,
    Top,
}

pub struct Timers {
    is_initiator: AtomicBool, // Is the owner of the timer the initiator or the responder for the last handshake?
    time_started: Instant,    // Start time of the tunnel
    timers: [AtomicUsize; TimerName::Top as usize],
}

impl Timers {
    pub fn new() -> Timers {
        Timers {
            is_initiator: AtomicBool::new(false),
            time_started: Instant::now(),
            timers: Default::default(),
        }
    }
}

impl Tunn {
    fn timer(&self, timer_name: TimerName) -> usize {
        self.timers.timers[timer_name as usize].load(Ordering::Relaxed)
    }

    pub fn timer_tick(&self, timer_name: TimerName) {
        self.timers.timers[timer_name as usize].store(
            self.timers.timers[TimerName::TimeCurrent as usize].load(Ordering::Relaxed),
            Ordering::Relaxed,
        )
    }

    pub fn timer_tick_session_established(&self, is_initiator: bool) {
        self.timer_tick(TimerName::TimeSessionEstablished);
        self.timers
            .is_initiator
            .store(is_initiator, Ordering::Relaxed)
    }

    pub fn update_timers(&self, dst: &mut [u8]) -> wireguard_result {
        let time = Instant::now();
        let timers = &self.timers;

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, because there is no real benefit to having highly accurate timers.
        let time_current = time.duration_since(timers.time_started).as_secs() as usize;
        timers.timers[TimerName::TimeCurrent as usize].store(time_current, Ordering::Relaxed);

        let time_session_established = self.timer(TimerName::TimeSessionEstablished);
        let time_last_packet_sent = self.timer(TimerName::TimeLastPacketSent);

        let mut hanshake_initiation_required = false;

        {
            if let Ok(mut handshake) = self.handshake.try_lock() {
                // Clear cookie after two minutes
                if handshake.has_cookie() {
                    let time_cookie_received = self.timer(TimerName::TimeCookieReceived);

                    if time_current - time_cookie_received >= COOKIE_EXPIRATION_TIME {
                        handshake.clear_cookie();
                    }
                }

                // If can't lock, then something is being upated anyway.
                if handshake.is_in_progress() {
                    if let Some(time_init_sent) = handshake.timer() {
                        let time_since_init_sent =
                            time.duration_since(time_init_sent).as_secs() as usize;
                        let time_since_started = self.timer(TimerName::TimeLastHandshakeStarted);

                        if time_current - time_since_started >= REKEY_ATTEMPT_TIME {
                            // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                            // the retries give up and cease, and clear all existing packets queued
                            // up to be sent. If a packet is explicitly queued up to be sent, then
                            // this timer is reset.
                            handshake.clear();

                            let mut cur_session = self.current_session.write().unwrap();
                            *cur_session = None;

                            let mut queued = self.packet_queue.lock().unwrap();
                            queued.clear();

                            self.log(Verbosity::Debug, "HANDSHAKE(REKEY_ATTEMPT_TIME)");

                            return wireguard_result {
                                op: result_type::WIREGUARD_ERROR,
                                size: 0,
                            };
                        }

                        if time_since_init_sent >= REKEY_TIMEOUT {
                            // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                            // if a response has not been received, where jitter is some random
                            // value between 0 and 333 ms.
                            self.log(Verbosity::Debug, "HANDSHAKE_RETRY(REKEY_TIMEOUT)");
                            hanshake_initiation_required = true;
                        }
                    }
                } else {
                    // If we have sent a packet to a given peer but have not received a
                    // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
                    // we initiate a new handshake.
                    let time_last_packet_received = self.timer(TimerName::TimeLastPacketReceived);
                    if time_current - time_last_packet_received >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
                    {
                        self.log(Verbosity::Debug, "HANDSHAKE(REKEY_TIMEOUT)");
                        hanshake_initiation_required = true;
                    }

                    let rekey_after = if timers.is_initiator.load(Ordering::Relaxed) {
                        // After sending a packet, if the sender was the original initiator
                        // of the handshake and if the current session key is REKEY_AFTER_TIME
                        // ms old, we initiate a new handshake. If the sender was the original
                        // responder of the handshake, it does not reinitiate a new handshake
                        // after REKEY_AFTER_TIME ms like the original initiator does.
                        REKEY_AFTER_TIME
                    } else {
                        // After receiving a packet, if the receiver was the original initiator
                        // of the handshake and if the current session key is REKEY_AFTER_TIME
                        // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
                        // handshake.
                        REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                    };

                    if time_current - time_session_established >= rekey_after {
                        self.log(Verbosity::Debug, "HANDSHAKE(REKEY_AFTER_TIME_TIMEOUT)");
                        hanshake_initiation_required = true;
                    }
                }
            }
        }

        // Packets are dropped if the session counter is greater than
        // REJECT_AFTER_MESSAGES or if its key is older than REJECT_AFTER_TIME.
        if time_current - time_session_established >= REJECT_AFTER_TIME {
            let mut cur_session = self.current_session.write().unwrap();
            if cur_session.take().is_some() {
                self.log(
                    Verbosity::Debug,
                    "CANCEL_SESSION(REJECT_AFTER_TIME_TIMEOUT)",
                );
            }
        }

        if hanshake_initiation_required {
            // Will also act as KEEPALIVE
            return self.format_handshake_initiation(dst, true);
        }

        // If a packet has been received from a given peer, but we have not
        // sent one back to the given peer in KEEPALIVE ms, we send an empty
        // packet.
        if time_current - time_last_packet_sent >= KEEPALIVE_TIMEOUT {
            self.log(Verbosity::Debug, "KEEPALIVE_TIMEOUT");
            return self.format_packet_data(&[], dst);
        }

        // All ephemeral private keys and symmetric session keys are zeroed
        // out after (REJECT_AFTER_TIME * 3) ms if no new keys have been
        // exchanged.

        //  TODO: since a session is closed after REJECT_AFTER_TIME seconds
        //  there is little value of zeroing the keys on the client side, if
        //  it is compromised, the keys are the least of our worries.

        // After sending a packet, if the number of packets sent using that
        // key exceed REKEY_AFTER_MESSAGES, we initiate a new handshake.

        //  TODO: the limit is so high that comparing against it is a waste of
        //  time. If it becomes lower in the future though it should be fixed.

        // Handshakes are only initiated once every REKEY_TIMEOUT ms, with this
        // strict rate limiting enforced.

        wireguard_result {
            op: result_type::WIREGUARD_DONE,
            size: 0,
        }
    }
}
