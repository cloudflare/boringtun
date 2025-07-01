// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult, N_SESSIONS};
use std::ops::{Index, IndexMut};

use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use std::time::{Duration, Instant};

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub(crate) const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);
pub(crate) const MAX_JITTER: Duration = Duration::from_millis(333);

/// Time-period after which a session should no longer be used for new packets.
///
/// In order for [`REKEY_AFTER_TIME`] to take effect, at least one data packet needs to be sent on a session.
/// If this data packet is sent close to the expire of the session ([`REJECT_AFTER_TIME`]), the session
/// may be expired by the time the packet reaches the receiver (and thus will not be able to be decrypted).
///
/// To avoid this, we stop using the session after [`REJECT_AFTER_TIME`] - [`KEEPALIVE_TIMEOUT`].
pub(crate) const SHOULD_NOT_USE_AFTER_TIME: Duration =
    Duration::from_secs(REJECT_AFTER_TIME.as_secs() - KEEPALIVE_TIMEOUT.as_secs());

#[derive(Debug)]
pub enum TimerName {
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
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

use self::TimerName::*;

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: bool,
    timers: [Instant; TimerName::Top as usize],
    /// Did we receive data without sending anything back?
    ///
    /// If `Some`, tracks the timestamp when we want to send a keepalive.
    want_passive_keepalive_at: Option<Instant>,
    /// Did we send data without hearing back?
    ///
    /// If `Some`, tracks the timestamp when we want to initiate the new handshake.
    want_handshake_at: Option<Instant>,
    persistent_keepalive: usize,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: bool,
    /// When we should sent a scheduled handshake.
    send_handshake_at: Option<Instant>,

    jitter_rng: StdRng,
}

impl Timers {
    pub(super) fn new(
        persistent_keepalive: Option<u16>,
        reset_rr: bool,
        rng_seed: u64,
        now: Instant,
    ) -> Timers {
        Timers {
            is_initiator: false,
            timers: [now; TimerName::Top as usize],
            want_passive_keepalive_at: Default::default(),
            want_handshake_at: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            should_reset_rr: reset_rr,
            send_handshake_at: None,
            jitter_rng: StdRng::seed_from_u64(rng_seed),
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    pub(crate) fn is_responder(&self) -> bool {
        !self.is_initiator()
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&mut self, now: Instant) {
        for t in &mut self.timers[..] {
            *t = now;
        }
        self.want_handshake_at = None;
        self.want_passive_keepalive_at = None;
    }
}

impl Index<TimerName> for Timers {
    type Output = Instant;
    fn index(&self, index: TimerName) -> &Self::Output {
        &self.timers[index as usize]
    }
}

impl IndexMut<TimerName> for Timers {
    fn index_mut(&mut self, index: TimerName) -> &mut Self::Output {
        &mut self.timers[index as usize]
    }
}

impl Tunn {
    pub(super) fn timer_tick(&mut self, timer_name: TimerName, now: Instant) {
        match timer_name {
            TimeLastPacketReceived => {
                self.timers.want_handshake_at = None;
            }
            TimeLastPacketSent => {
                self.timers.want_passive_keepalive_at = None;
            }
            TimeLastDataPacketReceived => {
                self.timers.want_passive_keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
            }
            TimeLastDataPacketSent => {
                match self.timers.want_handshake_at {
                    Some(_) => {
                        // This isn't the first timer tick (i.e. not the first packet)
                        // we haven't received a response to.
                    }
                    None => {
                        // We sent a packet and haven't heard back yet.
                        // Start a timer for when we want to make a new handshake.
                        self.timers.want_handshake_at =
                            Some(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)
                    }
                }
            }
            _ => {}
        }

        self.timers[timer_name] = now;
    }

    pub(super) fn timer_tick_session_established(&mut self, is_initiator: bool, now: Instant) {
        self.timer_tick(TimeSessionEstablished, now);
        self.timers.is_initiator = is_initiator;
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&mut self) {
        for session in &mut self.sessions {
            *session = None;
        }

        self.packet_queue.clear();

        self.timers.clear(Instant::now());
    }

    fn expire_sessions(&mut self, now: Instant) {
        for maybe_session in self.sessions.iter_mut() {
            let Some(session) = maybe_session else {
                continue;
            };

            if session.expired_at(now) {
                tracing::debug!(
                    message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                    session = session.receiving_index
                );
                *maybe_session = None;
            }
        }
    }

    #[deprecated(note = "Prefer `Timers::update_timers_at` to avoid time-impurity")]
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.update_timers_at(dst, Instant::now())
    }

    pub fn update_timers_at<'a>(&mut self, dst: &'a mut [u8], now: Instant) -> TunnResult<'a> {
        if let Some(scheduled_handshake_at) = self.timers.send_handshake_at {
            // If we have scheduled a handshake and the deadline expired, send it immediately.
            if now >= scheduled_handshake_at {
                self.timers.send_handshake_at = None;
                return self.format_handshake_initiation_at(dst, true, now);
            }

            debug_assert!(
                scheduled_handshake_at
                    .checked_duration_since(now)
                    .is_some_and(|remaining| remaining <= MAX_JITTER),
                "Should never suspend for longer than jitter duration"
            );

            // We have a handshake scheduled but the deadline is not expired yet.
            // Don't do anything to avoid repeated printing of logs.
            // The below logic would still evaluate that we need to send another handshake.
            return TunnResult::Done;
        }

        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        if self.timers.should_reset_rr {
            self.rate_limiter.reset_count_at(now);
        }

        self.expire_sessions(now);

        // In case our session expired, create a new one iff we initiated the previous one.
        if self.sessions[self.current % N_SESSIONS].is_none()
            && !self.handshake.is_in_progress()
            && self.timers.is_initiator()
        {
            handshake_initiation_required = true;
        }

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished];
        let handshake_started = self.timers[TimeLastHandshakeStarted];
        let data_packet_received = self.timers[TimeLastDataPacketReceived];
        let data_packet_sent = self.timers[TimeLastDataPacketSent];
        let persistent_keepalive = self.timers.persistent_keepalive;

        if self.handshake.is_expired() {
            return TunnResult::Err(WireGuardError::ConnectionExpired);
        }

        // Clear cookie after COOKIE_EXPIRATION_TIME
        if self
            .handshake
            .cookie_expiration()
            .is_some_and(|deadline| now >= deadline)
        {
            tracing::debug!("COOKIE_EXPIRED");
            self.handshake.clear_cookie();
        }

        // All ephemeral private keys and symmetric session keys are zeroed out after
        // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
        if now - session_established >= REJECT_AFTER_TIME * 3 {
            tracing::debug!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
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
                tracing::debug!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                self.handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if now.duration_since(time_init_sent) >= REKEY_TIMEOUT {
                // We avoid using `time` here, because it can be earlier than `time_init_sent`.
                // Once `checked_duration_since` is stable we can use that.
                // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                // if a response has not been received, where jitter is some random
                // value between 0 and 333 ms (`MAX_JITTER`).
                tracing::debug!("HANDSHAKE(REKEY_TIMEOUT)");
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
                    tracing::debug!(
                        "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT (on receive))"
                    );
                    handshake_initiation_required = true;
                }
            }

            // If we have sent a packet to a given peer but have not received a
            // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
            // we initiate a new handshake.
            if self
                .timers
                .want_handshake_at
                .is_some_and(|handshake_at| now >= handshake_at)
            {
                tracing::debug!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                handshake_initiation_required = true;
            }

            if !handshake_initiation_required {
                // If a packet has been received from a given peer, but we have not sent one back
                // to the given peer in KEEPALIVE ms, we send an empty packet.
                if self
                    .timers
                    .want_passive_keepalive_at
                    .is_some_and(|keepalive_at| now >= keepalive_at)
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
                    self.timer_tick(TimePersistentKeepalive, now);
                    keepalive_required = true;
                }
            }
        }

        if handshake_initiation_required {
            let jitter = self
                .timers
                .jitter_rng
                .gen_range(Duration::ZERO..=MAX_JITTER);

            let existing = self.timers.send_handshake_at.replace(now + jitter);
            debug_assert!(
                existing.is_none(),
                "Should never override existing handshake"
            );

            tracing::debug!(?jitter, "Scheduling new handshake");

            return TunnResult::Done;
        }

        if keepalive_required {
            return self.encapsulate_at(&[] as &[u8], dst, now);
        }

        TunnResult::Done
    }

    /// Returns an [`Instant`] when [`Tunn::update_timers_at`] should be called again.
    ///
    /// If this returns `None`, you may call it at your usual desired precision (usually once a second is enough).
    pub fn next_timer_update(&self) -> Option<Instant> {
        self.timers.send_handshake_at
    }

    #[deprecated(note = "Prefer `Tunn::time_since_last_handshake_at` to avoid time-impurity")]
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.time_since_last_handshake_at(Instant::now())
    }

    pub fn time_since_last_handshake_at(&self, now: Instant) -> Option<Duration> {
        let current_session = self.current;
        if self.sessions[current_session % super::N_SESSIONS].is_some() {
            let session_established_at = self.timers[TimeSessionEstablished];

            Some(now.duration_since(session_established_at))
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

    #[cfg(test)]
    pub fn set_persistent_keepalive(&mut self, keepalive: u16) {
        self.timers.persistent_keepalive = keepalive as usize;
    }
}
