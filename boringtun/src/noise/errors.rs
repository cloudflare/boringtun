// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub enum WireGuardError {
    DestinationBufferTooSmall,
    IncorrectPacketLength,
    UnexpectedPacket,
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
    LockFailed,
    ConnectionExpired,
    UnderLoad,
}
