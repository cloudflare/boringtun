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
}
