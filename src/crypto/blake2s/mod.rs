// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod tests;

pub struct Blake2s {
    inner: blake2s_simd::State,
    is_mac: bool,
    opad_key: [u8; 64],
}

impl Blake2s {
    fn new(key: &[u8], outlen: usize, mac: bool) -> Blake2s {
        let max_keylen = if mac { 64 } else { 32 }; // We truncate the key with no error, since the usage is internal

        let keylen = std::cmp::min(key.len(), max_keylen);
        let mut opad_key = [0x5c; 64];
        let mut ipad_key = [0x36; 64];
        let inner = if mac {
            let mut state = blake2s_simd::Params::new().hash_length(outlen).to_state();
            for i in 0..keylen {
                ipad_key[i] ^= key[i];
                opad_key[i] ^= key[i];
            }
            state.update(&ipad_key);
            state
        } else {
            blake2s_simd::Params::new()
                .hash_length(outlen)
                .key(key)
                .to_state()
        };
        Blake2s {
            inner,
            is_mac: mac,
            opad_key,
        }
    }

    pub fn new_mac(key: &[u8]) -> Blake2s {
        Blake2s::new(key, 16, false)
    }

    pub fn new_hash() -> Blake2s {
        Blake2s::new(&[], 32, false)
    }

    pub fn new_hmac(key: &[u8]) -> Blake2s {
        Blake2s::new(key, 32, true)
    }

    pub fn hash(&mut self, data: &[u8]) -> &mut Blake2s {
        self.inner.update(data);
        self
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let hash = if self.is_mac {
            let intermediate_hash = self.inner.finalize();
            let mut outer_state = blake2s_simd::State::new();
            outer_state.update(&self.opad_key);
            outer_state.update(intermediate_hash.as_bytes());
            outer_state.finalize()
        } else {
            self.inner.finalize()
        };
        let mut array = [0; 32];
        array[..hash.as_bytes().len()].copy_from_slice(hash.as_bytes());
        array
    }
}
