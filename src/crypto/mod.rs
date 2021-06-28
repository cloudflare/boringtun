// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Optimized cryptographic primitives for the WireGuard protocol.

mod blake2s;
mod chacha20poly1305;
mod x25519;

pub use blake2s::{constant_time_mac_check, Blake2s};
pub use chacha20poly1305::ChaCha20Poly1305;
pub use x25519::{X25519PublicKey, X25519SecretKey};

#[cfg(not(target_arch = "arm"))]
pub use ring::rand::SystemRandom;
#[cfg(target_arch = "arm")]
pub use x25519::SystemRandom;
