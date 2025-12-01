// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult};
use std::mem;
use std::ops::{Index, IndexMut};

use std::time::Duration;

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub enum TimerName {
    /// Current time, updated each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    /// Start time of the tunnel
    time_started: Instant,
    timers: [Duration; TimerName::Top as usize],
    pub(super) session_timers: [Duration; super::N_SESSIONS],
    /// Did we receive data without sending anything back?
    want_keepalive: bool,
    /// Did we send data without hearing back?
    want_handshake: bool,
    persistent_keepalive: usize,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<u16>, reset_rr: bool) -> Timers {
        Timers {
            is_initiator: false,
            time_started: Instant::now(),
            timers: Default::default(),
            session_timers: Default::default(),
            want_keepalive: Default::default(),
            want_handshake: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            should_reset_rr: reset_rr,
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self) {
        let now = Instant::now().duration_since(self.time_started);
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.want_handshake = false;
        self.want_keepalive = false;
    }
}

impl Index<TimerName> for Timers {
    type Output = Duration;
    fn index(&self, index: TimerName) -> &Duration {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Duration {
        &mut self.timers[index as usize]
    }
}

impl Tunn {
    pub(super) fn timer_tick(&mut self, timer_name: TimerName) {
        match timer_name {
            TimeLastPacketReceived => {
                self.timers.want_keepalive = true;
                self.timers.want_handshake = false;
            }
            TimeLastPacketSent => {
                self.timers.want_handshake = true;
                self.timers.want_keepalive = false;
            }
            _ => {}
        }

        let time = self.timers[TimeCurrent];
        self.timers[timer_name] = time;
    }

    pub(super) fn timer_tick_session_established(
        &mut self,
        is_initiator: bool,
        session_idx: usize,
    ) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS] =
            self.timers[TimeCurrent];
        self.timers.is_initiator = is_initiator;
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();

        self.timers.clear();
    }

    fn update_session_timers(&mut self, time_now: Duration) {
        let timers = &mut self.timers;

        for (i, t) in timers.session_timers.iter_mut().enumerate() {
            if time_now - *t > REJECT_AFTER_TIME {
                if let Some(session) = self.sessions[i].take() {
                    tracing::debug!(
                        message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                        session = session.receiving_index
                    );
                }
                *t = time_now;
            }
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        let time = Instant::now();

        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count();
        }

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = time.duration_since(self.timers.time_started);
        self.timers[TimeCurrent] = now;

        self.update_session_timers(now);

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished];
        let handshake_started = self.timers[TimeLastHandshakeStarted];
        let aut_packet_received = self.timers[TimeLastPacketReceived];
        let aut_packet_sent = self.timers[TimeLastPacketSent];
        let data_packet_received = self.timers[TimeLastDataPacketReceived];
        let data_packet_sent = self.timers[TimeLastDataPacketSent];
        let persistent_keepalive = self.timers.persistent_keepalive;

        {
            if self.handshake.is_expired() {
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            // Clear cookie after COOKIE_EXPIRATION_TIME
            if self.handshake.has_cookie()
                && now - self.timers[TimeCookieReceived] >= COOKIE_EXPIRATION_TIME
            {
                self.handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            if now - session_established >= REJECT_AFTER_TIME * 3 {
                tracing::error!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                self.handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = self.handshake.timer() {
                // Handshake Initiation Retransmission
                if now - handshake_started >= REKEY_ATTEMPT_TIME {
                    // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                    // the retries give up and cease, and clear all existing packets queued
                    // up to be sent. If a packet is explicitly queued up to be sent, then
                    // this timer is reset.
                    tracing::error!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                    self.handshake.set_expired();
                    self.clear_all();
                    return TunnResult::Err(WireGuardError::ConnectionExpired);
                }

                if time_init_sent.elapsed() >= REKEY_TIMEOUT {
                    // We avoid using `time` here, because it can be earlier than `time_init_sent`.
                    // Once `checked_duration_since` is stable we can use that.
                    // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                    // if a response has not been received, where jitter is some random
                    // value between 0 and 333 ms.
                    tracing::warn!("HANDSHAKE(REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }
            } else {
                if self.timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old, we initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not re-initiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    if session_established < data_packet_sent
                        && now - session_established >= REKEY_AFTER_TIME
                    {
                        tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        handshake_initiation_required = true;
                    }

                    // After receiving a packet, if the receiver was the original initiator
                    // of the handshake and if the current session key is REJECT_AFTER_TIME
                    // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
                    // handshake.
                    if session_established < data_packet_received
                        && now - session_established
                            >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                    {
                        tracing::warn!(
                            "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - \
                        REKEY_TIMEOUT \
                        (on receive))"
                        );
                        handshake_initiation_required = true;
                    }
                }

                // If we have sent a packet to a given peer but have not received a
                // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
                // we initiate a new handshake.
                if data_packet_sent > aut_packet_received
                    && now - aut_packet_received >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
                    && mem::replace(&mut self.timers.want_handshake, false)
                {
                    tracing::warn!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }

                if !handshake_initiation_required {
                    // If a packet has been received from a given peer, but we have not sent one back
                    // to the given peer in KEEPALIVE ms, we send an empty packet.
                    if data_packet_received > aut_packet_sent
                        && now - aut_packet_sent >= KEEPALIVE_TIMEOUT
                        && mem::replace(&mut self.timers.want_keepalive, false)
                    {
                        tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        keepalive_required = true;
                    }

                    // Persistent KEEPALIVE
                    if persistent_keepalive > 0
                        && (now - self.timers[TimePersistentKeepalive]
                            >= Duration::from_secs(persistent_keepalive as _))
                    {
                        tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                        self.timer_tick(TimePersistentKeepalive);
                        keepalive_required = true;
                    }
                }
            }
        }

        if handshake_initiation_required {
            return self.format_handshake_initiation(dst, true);
        }

        if keepalive_required {
            return self.encapsulate(&[], dst);
        }

        TunnResult::Done
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let current_session = self.current;
        if self.sessions[current_session % super::N_SESSIONS].is_some() {
            let duration_since_tun_start = Instant::now().duration_since(self.timers.time_started);
            let duration_since_session_established = self.timers[TimeSessionEstablished];

            Some(duration_since_tun_start - duration_since_session_established)
        } else {
            None
        }
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive;

        if keepalive > 0 {
            Some(keepalive as u16)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Tunn;
    use crate::x25519;
    use std::thread;

    fn create_test_tunn() -> Tunn {
        let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public_key = x25519::PublicKey::from([1u8; 32]);
        Tunn::new(private_key, public_key, None, None, 0, None)
    }

    #[test]
    fn test_timers_creation() {
        let timers = Timers::new(Some(25), true);
        assert_eq!(timers.persistent_keepalive, 25);
        assert!(timers.should_reset_rr);
        assert!(!timers.is_initiator);
        assert!(!timers.want_handshake);
        assert!(!timers.want_keepalive);
    }

    #[test]
    fn test_timers_creation_no_keepalive() {
        let timers = Timers::new(None, false);
        assert_eq!(timers.persistent_keepalive, 0);
        assert!(!timers.should_reset_rr);
    }

    #[test]
    fn test_timer_indexing() {
        let mut timers = Timers::new(Some(10), false);
        let test_duration = Duration::from_secs(42);
        
        // Test index assignment and retrieval
        timers[TimeLastPacketReceived] = test_duration;
        assert_eq!(timers[TimeLastPacketReceived], test_duration);
        
        timers[TimeSessionEstablished] = Duration::from_secs(100);
        assert_eq!(timers[TimeSessionEstablished], Duration::from_secs(100));
    }

    #[test]
    fn test_is_initiator() {
        let mut timers = Timers::new(None, false);
        assert!(!timers.is_initiator());
        
        timers.is_initiator = true;
        assert!(timers.is_initiator());
    }

    #[test]
    fn test_timers_clear() {
        let mut timers = Timers::new(None, false);
        timers.want_handshake = true;
        timers.want_keepalive = true;
        
        // All timers should be reset to current time
        let before_clear = Instant::now().duration_since(timers.time_started);
        thread::sleep(Duration::from_millis(10));
        timers.clear();
        
        // All timer values should be >= before_clear time
        for timer_val in &timers.timers {
            assert!(*timer_val >= before_clear);
        }
        
        assert!(!timers.want_handshake);
        assert!(!timers.want_keepalive);
    }

    #[test]
    fn test_timer_tick_packet_received() {
        let mut tunn = create_test_tunn();
        
        tunn.timer_tick(TimeLastPacketReceived);
        
        assert!(tunn.timers.want_keepalive);
        assert!(!tunn.timers.want_handshake);
    }

    #[test]
    fn test_timer_tick_packet_sent() {
        let mut tunn = create_test_tunn();
        
        tunn.timer_tick(TimeLastPacketSent);
        
        assert!(!tunn.timers.want_keepalive);
        assert!(tunn.timers.want_handshake);
    }

    #[test]
    fn test_timer_tick_other_events() {
        let mut tunn = create_test_tunn();
        let initial_want_keepalive = tunn.timers.want_keepalive;
        let initial_want_handshake = tunn.timers.want_handshake;
        
        tunn.timer_tick(TimeSessionEstablished);
        
        // Other timer events should not affect want flags
        assert_eq!(tunn.timers.want_keepalive, initial_want_keepalive);
        assert_eq!(tunn.timers.want_handshake, initial_want_handshake);
    }

    #[test]
    fn test_timer_tick_session_established() {
        let mut tunn = create_test_tunn();
        let session_idx = 1;
        
        tunn.timer_tick_session_established(true, session_idx);
        
        assert!(tunn.timers.is_initiator);
        assert_eq!(
            tunn.timers.session_timers[session_idx % crate::noise::N_SESSIONS],
            tunn.timers[TimeCurrent]
        );
        assert_eq!(tunn.timers[TimeSessionEstablished], tunn.timers[TimeCurrent]);
    }

    #[test]
    fn test_persistent_keepalive_getter() {
        let tunn_with_keepalive = {
            let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
            let public_key = x25519::PublicKey::from([1u8; 32]);
            Tunn::new(private_key, public_key, None, Some(30), 0, None)
        };
        
        let tunn_without_keepalive = {
            let private_key = x25519::StaticSecret::random_from_rng(&mut rand_core::OsRng);
            let public_key = x25519::PublicKey::from([1u8; 32]);
            Tunn::new(private_key, public_key, None, None, 0, None)
        };
        
        assert_eq!(tunn_with_keepalive.persistent_keepalive(), Some(30));
        assert_eq!(tunn_without_keepalive.persistent_keepalive(), None);
    }

    #[test]
    fn test_time_since_last_handshake_no_session() {
        let tunn = create_test_tunn();
        
        // No active session should return None
        assert_eq!(tunn.time_since_last_handshake(), None);
    }

    #[test]
    fn test_clear_all() {
        let mut tunn = create_test_tunn();
        
        // Set up some state
        tunn.timers.want_handshake = true;
        tunn.timers.want_keepalive = true;
        
        tunn.clear_all();
        
        // Verify all state is cleared
        assert!(!tunn.timers.want_handshake);
        assert!(!tunn.timers.want_keepalive);
        assert!(tunn.packet_queue.is_empty());
        
        // All sessions should be None
        for session in &tunn.sessions {
            assert!(session.is_none());
        }
    }

    #[test]
    fn test_update_timers_basic() {
        let mut tunn = create_test_tunn();
        let mut dst = [0u8; 1024];
        
        // Basic timer update should not require action
        let result = tunn.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::Done));
    }

    #[test]
    fn test_session_timer_expiry() {
        let mut tunn = create_test_tunn();
        
        // Set up an old session timer
        let very_old_time = Duration::from_secs(1);
        tunn.timers.session_timers[0] = very_old_time;
        let current_time = Duration::from_secs(200); // > REJECT_AFTER_TIME
        
        tunn.update_session_timers(current_time);
        
        // Timer should be reset to current time
        assert_eq!(tunn.timers.session_timers[0], current_time);
    }

    #[test]
    fn test_session_timer_not_expired() {
        let mut tunn = create_test_tunn();
        
        // Set up a recent session timer
        let recent_time = Duration::from_secs(100);
        tunn.timers.session_timers[0] = recent_time;
        let current_time = Duration::from_secs(150); // < recent_time + REJECT_AFTER_TIME
        
        tunn.update_session_timers(current_time);
        
        // Timer should remain unchanged
        assert_eq!(tunn.timers.session_timers[0], recent_time);
    }

    #[test]
    fn test_timer_constants_validity() {
        // Ensure timer constants make sense relative to each other
        assert!(REKEY_AFTER_TIME < REJECT_AFTER_TIME);
        assert!(REKEY_ATTEMPT_TIME < REJECT_AFTER_TIME);
        assert!(REKEY_TIMEOUT < REKEY_ATTEMPT_TIME);
        assert!(KEEPALIVE_TIMEOUT < REKEY_AFTER_TIME);
        
        // Check specific relationships from WireGuard spec
        assert_eq!(REKEY_AFTER_TIME, Duration::from_secs(120));
        assert_eq!(REJECT_AFTER_TIME, Duration::from_secs(180));
        assert_eq!(REKEY_ATTEMPT_TIME, Duration::from_secs(90));
        assert_eq!(REKEY_TIMEOUT, Duration::from_secs(5));
        assert_eq!(KEEPALIVE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(COOKIE_EXPIRATION_TIME, Duration::from_secs(120));
    }

    #[test]
    fn test_timer_name_variants() {
        // Ensure all timer variants can be used as indices
        let timers = Timers::new(None, false);
        
        let _current = &timers[TimeCurrent];
        let _session = &timers[TimeSessionEstablished];
        let _handshake = &timers[TimeLastHandshakeStarted];
        let _packet_recv = &timers[TimeLastPacketReceived];
        let _packet_sent = &timers[TimeLastPacketSent];
        let _data_recv = &timers[TimeLastDataPacketReceived];
        let _data_sent = &timers[TimeLastDataPacketSent];
        let _cookie = &timers[TimeCookieReceived];
        let _keepalive = &timers[TimePersistentKeepalive];
    }

    #[test]
    fn test_timer_array_bounds() {
        // Ensure the timer array has the correct size
        let timers = Timers::new(None, false);
        assert_eq!(timers.timers.len(), TimerName::Top as usize);
        assert_eq!(timers.session_timers.len(), super::super::N_SESSIONS);
    }

    #[cfg(feature = "mock-instant")]
    #[test]
    fn test_timer_with_mock_instant() {
        use mock_instant::MockClock;
        
        let start_time = Instant::now();
        let timers = Timers::new(Some(10), false);
        
        // Advance mock time
        MockClock::advance(Duration::from_secs(5));
        
        let elapsed = Instant::now().duration_since(start_time);
        assert_eq!(elapsed, Duration::from_secs(5));
        
        // Timer creation time should be earlier than current mock time
        let now_duration = Instant::now().duration_since(timers.time_started);
        assert!(now_duration >= Duration::from_secs(5));
    }

    #[test] 
    fn test_concurrent_timer_access() {
        use std::sync::{Arc, Mutex};
        
        let tunn = Arc::new(Mutex::new(create_test_tunn()));
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let tunn_clone = Arc::clone(&tunn);
                thread::spawn(move || {
                    for j in 0..10 {
                        let mut t = tunn_clone.lock().unwrap();
                        if i % 2 == 0 {
                            t.timer_tick(TimeLastPacketReceived);
                        } else {
                            t.timer_tick(TimeLastPacketSent);
                        }
                        
                        if j % 3 == 0 {
                            t.timer_tick_session_established(i % 2 == 0, i);
                        }
                    }
                })
            })
            .collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Should complete without panics
        let final_tunn = tunn.lock().unwrap();
        // Just verify the timer was initialized (duration_since will be >= 0)
        assert!(Instant::now().duration_since(final_tunn.timers.time_started) >= Duration::from_secs(0));
    }
}
