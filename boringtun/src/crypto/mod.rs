// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Optimized cryptographic primitives for the WireGuard protocol.

mod blake2s;
mod chacha20poly1305;

pub use blake2s::{constant_time_mac_check, Blake2s};
pub use chacha20poly1305::ChaCha20Poly1305;

pub use ring::rand::SystemRandom;
