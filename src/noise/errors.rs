// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[derive(Debug)]
#[repr(C)]
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
    InvalidPacket,
    NoCurrentSession,
    LockFailed,
    ConnectionExpired,
    UnderLoad,
}
