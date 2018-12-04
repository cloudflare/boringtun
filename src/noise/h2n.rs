#[inline(always)]
pub fn write_u32(v: u32, buf: &mut [u8]) {
    assert!(buf.len() >= 4);
    buf[0] = v as u8;
    buf[1] = (v >> 8) as u8;
    buf[2] = (v >> 16) as u8;
    buf[3] = (v >> 24) as u8;
}

#[inline(always)]
pub fn write_u32_be(v: u32, buf: &mut [u8]) {
    assert!(buf.len() >= 4);
    buf[3] = v as u8;
    buf[2] = (v >> 8) as u8;
    buf[1] = (v >> 16) as u8;
    buf[0] = (v >> 24) as u8;
}

#[inline(always)]
pub fn write_u64(v: u64, buf: &mut [u8]) {
    assert!(buf.len() >= 8);
    buf[0] = v as u8;
    buf[1] = (v >> 8) as u8;
    buf[2] = (v >> 16) as u8;
    buf[3] = (v >> 24) as u8;
    buf[4] = (v >> 32) as u8;
    buf[5] = (v >> 40) as u8;
    buf[6] = (v >> 48) as u8;
    buf[7] = (v >> 56) as u8;
}

#[inline(always)]
pub fn write_u64_be(v: u64, buf: &mut [u8]) {
    assert!(buf.len() >= 8);
    buf[7] = v as u8;
    buf[6] = (v >> 8) as u8;
    buf[5] = (v >> 16) as u8;
    buf[4] = (v >> 24) as u8;
    buf[3] = (v >> 32) as u8;
    buf[2] = (v >> 40) as u8;
    buf[1] = (v >> 48) as u8;
    buf[0] = (v >> 56) as u8;
}

#[inline(always)]
pub fn read_u16_be(buf: &[u8]) -> u16 {
    assert!(buf.len() >= 2);
    return (buf[1] as u16) | ((buf[0] as u16) << 8);
}

#[inline(always)]
pub fn read_u32(buf: &[u8]) -> u32 {
    assert!(buf.len() >= 4);
    return (buf[0] as u32) | (buf[1] as u32) << 8 | (buf[2] as u32) << 16 | (buf[3] as u32) << 24;
}

#[inline(always)]
pub fn read_u32_be(buf: &[u8]) -> u32 {
    assert!(buf.len() >= 4);
    return (buf[3] as u32) | (buf[2] as u32) << 8 | (buf[1] as u32) << 16 | (buf[0] as u32) << 24;
}

#[inline(always)]
pub fn read_u64(buf: &[u8]) -> u64 {
    assert!(buf.len() >= 8);
    return (buf[0] as u64)
        | (buf[1] as u64) << 8
        | (buf[2] as u64) << 16
        | (buf[3] as u64) << 24
        | (buf[4] as u64) << 32
        | (buf[5] as u64) << 40
        | (buf[6] as u64) << 48
        | (buf[7] as u64) << 56;
}

#[inline(always)]
pub fn read_u64_be(buf: &[u8]) -> u64 {
    assert!(buf.len() >= 8);
    return (buf[7] as u64)
        | (buf[6] as u64) << 8
        | (buf[5] as u64) << 16
        | (buf[4] as u64) << 24
        | (buf[3] as u64) << 32
        | (buf[2] as u64) << 40
        | (buf[1] as u64) << 48
        | (buf[0] as u64) << 56;
}
