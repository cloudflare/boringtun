// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! # Experimental NIZK (Non-Interactive Zero-Knowledge) Proof Module
//!
//! This module implements a **Schnorr Proof-of-Knowledge** over the **Ristretto255** group,
//! transformed into a Non-Interactive Zero-Knowledge proof using the **Fiat-Shamir heuristic**
//! with **Blake2s** as the random oracle.
//!
//! ## Protocol (Sigma/Schnorr PoK)
//!
//! Given a secret key `sk` and public key `pk = sk * G` (G is the Ristretto255 generator):
//!
//! ### Prove
//! 1. Sample random nonce `k` from `OsRng`
//! 2. Compute commitment: `R = k * G`
//! 3. Compute Fiat-Shamir challenge: `c = Blake2s(label || pk_bytes || R_bytes || msg)`
//! 4. Compute response: `s = k + c * sk` (in the scalar field)
//! 5. Proof = `(R, s)`
//!
//! ### Verify
//! 1. Recompute challenge: `c = Blake2s(label || pk_bytes || R_bytes || msg)`
//! 2. Check: `s * G == R + c * pk`
//!
//! ## Security Notes
//! - The nonce `k` is sampled freshly from the OS RNG for each proof (non-deterministic).
//! - This provides zero-knowledge even under repeated use.
//! - **Soundness**: Breaking this requires solving the discrete log problem on Ristretto255.
//! - This module is **experimental** and has not undergone formal security review.
//!
//! ## Feature Gate
//! This module is only compiled when the `experimental-nizk` feature is enabled.

#![cfg(feature = "experimental-nizk")]

use blake2::{Blake2s256, Digest};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

/// Domain-separation label for the Fiat-Shamir hash
const NIZK_LABEL: &[u8] = b"boringtun-nizk-v2-ed25519-pok";

/// A Schnorr Proof-of-Knowledge (PoK) over Ed25519.
///
/// Contains:
/// - `R`: The commitment point `k * G`, compressed to 32 bytes (CompressedEdwardsY).
/// - `s`: The scalar response `k + c * sk`, 32 bytes.
///
/// Total serialized size: **64 bytes**.
#[derive(Debug, Clone, PartialEq)]
pub struct NizkProof {
    /// The commitment: `R = k * G` (32 bytes, compressed Edwards point)
    pub r_bytes: [u8; 32],
    /// The response: `s = k + c * sk` (32 bytes, Ristretto scalar)
    pub s_bytes: [u8; 32],
}

impl NizkProof {
    /// Serialize the proof to a 64-byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.r_bytes);
        buf[32..].copy_from_slice(&self.s_bytes);
        buf
    }

    /// Deserialize a proof from a 64-byte slice.
    pub fn from_bytes(data: &[u8; 64]) -> Self {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&data[..32]);
        s_bytes.copy_from_slice(&data[32..]);
        NizkProof { r_bytes, s_bytes }
    }
}

/// Compute the Fiat-Shamir challenge scalar.
///
/// `c = Blake2s(NIZK_LABEL || pk_bytes || r_bytes || msg)`
fn fiat_shamir_challenge(pk_bytes: &[u8; 32], r_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut hasher = Blake2s256::new();
    hasher.update(NIZK_LABEL);
    hasher.update(pk_bytes);
    hasher.update(r_bytes);
    hasher.update(msg);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(hash)
}

/// Prove knowledge of `sk` such that `pk_montgomery = sk * G_montgomery`.
///
/// This actually proves knowledge of `sk` such that `pk_edwards = sk * G_edwards`,
/// where `pk_edwards` is one of the two Edwards points corresponding to the 
/// given x25519 Montgomery public key.
pub fn prove(sk_bytes: &[u8; 32], pk_bytes: &[u8; 32], msg: &[u8]) -> NizkProof {
    // Step 1: Sample random nonce k
    let k = Scalar::random(&mut OsRng);

    // Step 2: Compute commitment R = k * G
    let r_point = ED25519_BASEPOINT_POINT * k;
    let r_bytes = r_point.compress().to_bytes();

    // Step 3: Compute Fiat-Shamir challenge c
    // We use the Montgomery public key bytes for domain separation
    let c = fiat_shamir_challenge(pk_bytes, &r_bytes, msg);

    // Step 4: Convert secret key to a scalar
    // x25519 keys MUST be clamped TO MATCH the public key derivation.
    let mut clamped = *sk_bytes;
    clamped[0]  &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let sk_scalar = Scalar::from_bytes_mod_order(clamped);

    // Step 5: Compute response s = k + c * sk
    let s = k + c * sk_scalar;
    let s_bytes = s.to_bytes();

    NizkProof { r_bytes, s_bytes }
}

/// Verify a `NizkProof` against an x25519 public key.
///
/// Since x25519 keys lack a sign bit when mapped to Edwards, we check both 
/// possible sign bit lifts.
pub fn verify(pk_bytes: &[u8; 32], proof: &NizkProof, msg: &[u8]) -> bool {
    // 1. Reconstruct Montgomery Point
    let pk_m = MontgomeryPoint(*pk_bytes);
    
    // 2. Lift to Edwards (try both signs: 0 and 1)
    let pk_e0 = pk_m.to_edwards(0);
    let pk_e1 = pk_m.to_edwards(1);

    let verify_single = |pk_e: Option<EdwardsPoint>| -> bool {
        let pk_point = match pk_e {
            Some(p) => p,
            None => return false,
        };

        let r_compressed = CompressedEdwardsY(proof.r_bytes);
        let r_point = match r_compressed.decompress() {
            Some(p) => p,
            None => return false,
        };

        let s_ct = Scalar::from_canonical_bytes(proof.s_bytes);
        let s = if bool::from(s_ct.is_some()) {
            s_ct.unwrap()
        } else {
            return false;
        };

        let c = fiat_shamir_challenge(pk_bytes, &proof.r_bytes, msg);

        // Check s*G == R + c*PK
        let lhs = ED25519_BASEPOINT_POINT * s;
        let rhs = r_point + (pk_point * c);
        lhs == rhs
    };

    verify_single(pk_e0) || verify_single(pk_e1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    /// Generate a random x25519-style 32-byte secret key and its Montgomery public key.
    fn random_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        let mut sk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut sk_bytes);
        // Map to Montgomery
        let sk_scalar = Scalar::from_bytes_mod_order(sk_bytes);
        let pk_edwards = ED25519_BASEPOINT_POINT * sk_scalar;
        let pk_montgomery = pk_edwards.to_montgomery();
        (sk_bytes, pk_montgomery.to_bytes())
    }

    #[test]
    fn test_nizk_prove_and_verify() {
        let (sk, pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";

        let proof = prove(&sk, &pk, msg);
        assert!(
            verify(&pk, &proof, msg),
            "Valid proof should verify successfully for x25519 key"
        );
    }

    #[test]
    fn test_nizk_different_message_rejected() {
        let (sk, pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";
        let wrong_msg = b"completely-different-message";

        let proof = prove(&sk, &pk, msg);
        assert!(
            !verify(&pk, &proof, wrong_msg),
            "Proof with wrong message should be rejected"
        );
    }

    #[test]
    fn test_nizk_tampered_r_rejected() {
        let (sk, pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";

        let mut proof = prove(&sk, &pk, msg);
        proof.r_bytes[0] ^= 0x01;

        assert!(
            !verify(&pk, &proof, msg),
            "Tampered commitment R should be rejected"
        );
    }

    #[test]
    fn test_nizk_tampered_s_rejected() {
        let (sk, pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";

        let mut proof = prove(&sk, &pk, msg);
        proof.s_bytes[0] ^= 0x01;

        assert!(
            !verify(&pk, &proof, msg),
            "Tampered response s should be rejected"
        );
    }

    #[test]
    fn test_nizk_wrong_public_key_rejected() {
        let (sk, pk) = random_x25519_keypair();
        let (_, wrong_pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";

        let proof = prove(&sk, &pk, msg);
        assert!(
            !verify(&wrong_pk, &proof, msg),
            "Proof verified against wrong public key should be rejected"
        );
    }

    #[test]
    fn test_nizk_serialization_roundtrip() {
        let (sk, pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";

        let proof = prove(&sk, &pk, msg);
        let bytes = proof.to_bytes();
        let proof2 = NizkProof::from_bytes(&bytes);

        assert_eq!(proof, proof2, "Serialization roundtrip should be lossless");
        assert!(
            verify(&pk, &proof2, msg),
            "Deserialized proof should still verify"
        );
    }

    #[test]
    fn test_nizk_randomness_different_proofs() {
        let (sk, pk) = random_x25519_keypair();
        let msg = b"wireguard-handshake-transcript";

        let proof1 = prove(&sk, &pk, msg);
        let proof2 = prove(&sk, &pk, msg);

        assert_ne!(
            proof1.r_bytes, proof2.r_bytes,
            "Two proofs for same key should have different commitment R (random k)"
        );
        assert!(verify(&pk, &proof1, msg));
        assert!(verify(&pk, &proof2, msg));
    }
}
