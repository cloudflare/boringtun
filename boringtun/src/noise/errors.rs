// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::fmt::Display;

#[derive(Debug)]
pub enum WireGuardError {
    DestinationBufferTooSmall,
    #[deprecated = "Unused"]
    IncorrectPacketLength,
    UnexpectedPacket,
    #[deprecated = "Unused"]
    WrongPacketType,
    WrongIndex,
    WrongKey,
    InvalidTai64nTimestamp,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    #[deprecated = "Unused"]
    LockFailed,
    ConnectionExpired,
    UnderLoad,
}

impl Display for WireGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[expect(deprecated, reason = "We need to handle all cases.")]
        match self {
            WireGuardError::DestinationBufferTooSmall => {
                write!(f, "the destination buffer is too small")
            }
            WireGuardError::UnexpectedPacket => write!(
                f,
                "packet of this type was not expected in the current state"
            ),
            WireGuardError::WrongIndex => write!(f, "index in packet did not match local state"),
            WireGuardError::WrongKey => write!(
                f,
                "decrypted public key from handshake initiation did not match expected key"
            ),
            WireGuardError::InvalidTai64nTimestamp => write!(f, "timestamp is less than 12bytes"),
            WireGuardError::WrongTai64nTimestamp => {
                write!(f, "timestamp of packet is in the past; possible a replay?")
            }
            WireGuardError::InvalidMac => {
                write!(f, "MAC mismatch in packet")
            }
            WireGuardError::InvalidAeadTag => write!(f, "failed to decrypt packet data"),
            WireGuardError::InvalidCounter => {
                write!(f, "packet counter is too old")
            }
            WireGuardError::DuplicateCounter => {
                write!(f, "packet with same counter already processed")
            }
            WireGuardError::InvalidPacket => {
                write!(f, "failed to parse packet (too short / invalid type / etc)")
            }
            WireGuardError::NoCurrentSession => write!(f, "no active session"),
            WireGuardError::ConnectionExpired => write!(f, "connection is expired"),
            WireGuardError::UnderLoad => write!(f, "rate limit exceeded"),
            WireGuardError::IncorrectPacketLength => Ok(()),
            WireGuardError::WrongPacketType => Ok(()),
            WireGuardError::LockFailed => Ok(()),
        }
    }
}

impl std::error::Error for WireGuardError {}
