// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use self::TimerName::*;
use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult, Verbosity};
use std::ops::Index;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/*
static MAX_TIMER_HANDSHAKES: u32 = 90 / 5;
static COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);
static HANDSHAKE_INITIATION_RATE: Duration = Duration::from_millis(50);
*/

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TimerName {
    TimeCurrent,                // Current time, updated each call to `update_timers`
    TimeSessionEstablished,     // Time when last handshake was completed
    TimeLastHandshakeStarted,   // Time the last attempt for a new handshake began
    TimeLastPacketReceived,     // Time we last received and authenticated a packet
    TimeLastPacketSent,         // Time we last send a packet
    TimeLastDataPacketReceived, // Time we last received and authenticated a DATA packet
    TimeLastDataPacketSent,     // Time we last send a DATA packet
    TimeCookieReceived,         // Time we last received a cookie
    TimePersistentKeepalive,    // Time we last sent persistent keepalive
    Top,
}

// Although technically there are data races in play, but in practice
// * Timers are only checked periodically so it is safe to assume all (Relaxed) atomic access will be serialized anyway
// * Even if some timer is triggered with a tiny delay there is no harm in that
#[derive(Default, Debug)]
pub struct Timer {
    time: AtomicUsize,
}

#[derive(Debug)]
pub struct Timers {
    is_initiator: AtomicBool, // Is the owner of the timer the initiator or the responder for the last handshake?
    time_started: Instant,    // Start time of the tunnel
    timers: [Timer; TimerName::Top as usize],
    want_keepalive: AtomicBool, // Did we receive data without sending anything back?
    want_handshake: AtomicBool, // Did we send data without hearing back?
    persistent_keepalive: AtomicUsize,
}

impl Timers {
    pub fn new(persistent_keepalive: Option<u16>) -> Timers {
        Timers {
            is_initiator: AtomicBool::new(false),
            time_started: Instant::now(),
            timers: Default::default(),
            want_keepalive: Default::default(),
            want_handshake: Default::default(),
            persistent_keepalive: AtomicUsize::new(usize::from(persistent_keepalive.unwrap_or(0))),
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator.load(Ordering::Relaxed)
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference timeframe is the same
    pub fn clear(&self) {
        let now = Instant::now().duration_since(self.time_started);
        for t in &self.timers[..] {
            t.set(now);
        }
        self.want_handshake.store(false, Ordering::Relaxed);
        self.want_keepalive.store(false, Ordering::Relaxed);
    }
}

impl Index<TimerName> for Timers {
    type Output = Timer;
    fn index(&self, index: TimerName) -> &Timer {
        &self.timers[index as usize]
    }
}

impl Timer {
    fn time(&self) -> Duration {
        Duration::from_secs(self.time.load(Ordering::Relaxed) as _)
    }

    fn set(&self, val: Duration) {
        self.time.store(val.as_secs() as _, Ordering::Relaxed);
    }
}

impl Tunn {
    pub fn tick_handshake_started(&self) {
        self.timers[TimeLastHandshakeStarted].set(self.timers[TimeCurrent].time());
    }

    pub fn timer_tick(&self, timer_name: TimerName) {
        match timer_name {
            TimeLastPacketReceived => {
                self.timers.want_keepalive.store(true, Ordering::Relaxed);
                self.timers.want_handshake.store(false, Ordering::Relaxed);
            }
            TimeLastPacketSent => {
                self.timers.want_handshake.store(true, Ordering::Relaxed);
                self.timers.want_keepalive.store(false, Ordering::Relaxed);
            }
            _ => {}
        }

        self.timers[timer_name].set(self.timers[TimeCurrent].time());
    }

    pub fn timer_tick_session_established(&self, is_initiator: bool) {
        self.timer_tick(TimeSessionEstablished);
        self.timers
            .is_initiator
            .store(is_initiator, Ordering::Relaxed)
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference timeframe is the same
    fn clear_all(&self) {
        for session in &self.sessions {
            *session.write() = None;
        }

        {
            let mut queued = self.packet_queue.lock();
            queued.clear();
        }

        self.timers.clear();
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let mut hanshake_initiation_required = false;
        let mut keepalive_required = false;

        let time = Instant::now();
        let timers = &self.timers;

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = time.duration_since(timers.time_started);
        timers[TimeCurrent].set(now);

        // Load timers only once:
        let session_established = timers[TimeSessionEstablished].time();
        let handshake_started = timers[TimeLastHandshakeStarted].time();
        let aut_packet_received = timers[TimeLastPacketReceived].time();
        let aut_packet_sent = timers[TimeLastPacketSent].time();
        let data_packet_received = timers[TimeLastDataPacketReceived].time();
        let data_packet_sent = timers[TimeLastDataPacketSent].time();
        let persistent_keepalive = timers.persistent_keepalive.load(Ordering::Relaxed);

        {
            let mut handshake = match self.handshake.try_lock() {
                Some(handshake) => handshake,
                None => return TunnResult::Done,
            };

            if handshake.is_expired() {
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            // Clear cookie after COOKIE_EXPIRATION_TIME
            if handshake.has_cookie()
                && now - timers[TimeCookieReceived].time() >= COOKIE_EXPIRATION_TIME
            {
                handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            if now - session_established >= REJECT_AFTER_TIME * 3 {
                self.log(Verbosity::Info, "CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = handshake.timer() {
                // Handshake Initiation Retransmission
                if now - handshake_started >= REKEY_ATTEMPT_TIME {
                    // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                    // the retries give up and cease, and clear all existing packets queued
                    // up to be sent. If a packet is explicitly queued up to be sent, then
                    // this timer is reset.
                    self.log(Verbosity::Info, "CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                    handshake.set_expired();
                    self.clear_all();
                    return TunnResult::Err(WireGuardError::ConnectionExpired);
                }

                if time.duration_since(time_init_sent) >= REKEY_TIMEOUT {
                    // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                    // if a response has not been received, where jitter is some random
                    // value between 0 and 333 ms.
                    self.log(Verbosity::Debug, "HANDSHAKE(REKEY_TIMEOUT)");
                    hanshake_initiation_required = true;
                }
            } else {
                if timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old, we initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not reinitiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    if session_established < data_packet_sent
                        && now - session_established >= REKEY_AFTER_TIME
                    {
                        self.log(Verbosity::Debug, "HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        hanshake_initiation_required = true;
                    }

                    // After receiving a packet, if the receiver was the original initiator
                    // of the handshake and if the current session key is REJECT_AFTER_TIME
                    // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
                    // handshake.
                    if session_established < data_packet_received
                        && now - session_established
                            >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                    {
                        self.log(
                        Verbosity::Debug,
                        "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT (on receive))",
                    );
                        hanshake_initiation_required = true;
                    }
                }

                // If we have sent a packet to a given peer but have not received a
                // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
                // we initiate a new handshake.
                if now - aut_packet_received >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
                    && timers.want_handshake.swap(false, Ordering::Relaxed)
                {
                    self.log(Verbosity::Debug, "HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    hanshake_initiation_required = true;
                }

                if !hanshake_initiation_required {
                    // If a packet has been received from a given peer, but we have not sent one back
                    // to the given peer in KEEPALIVE ms, we send an empty packet.
                    if now - aut_packet_sent >= KEEPALIVE_TIMEOUT
                        && timers.want_keepalive.swap(false, Ordering::Relaxed)
                    {
                        self.log(Verbosity::Debug, "KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        keepalive_required = true;
                    }

                    // Persistent KEEPALIVE
                    if persistent_keepalive > 0
                        && (now - timers[TimePersistentKeepalive].time()
                            >= Duration::from_secs(persistent_keepalive as _))
                    {
                        self.log(Verbosity::Debug, "KEEPALIVE(PERSISTENT_KEEPALIVE)");
                        self.timer_tick(TimePersistentKeepalive);
                        keepalive_required = true;
                    }
                }
            }
        }

        if hanshake_initiation_required {
            return self.format_handshake_initiation(dst, true);
        }

        if keepalive_required {
            return self.tunnel_to_network(&[], dst);
        }

        TunnResult::Done
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let current_session = self.current.load(Ordering::Acquire);
        if self.sessions[current_session % super::N_SESSIONS]
            .read()
            .is_some()
        {
            let time_current = Instant::now().duration_since(self.timers.time_started);
            let time_session_established = self.timers[TimeSessionEstablished].time();
            let epoch_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

            Some(epoch_time - (time_current - time_session_established))
        } else {
            None
        }
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive.load(Ordering::Relaxed);

        if keepalive > 0 {
            Some(keepalive as u16)
        } else {
            None
        }
    }
}
