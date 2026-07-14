// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 Aspenini (orbis-unpkg)
// SPDX-License-Identifier: GPL-2.0-or-later

//! Cryptographic primitives used to unpack a PKG.
//!
//! This is a faithful port of the original shadPS4 `Crypto` class:
//! PKCS#1 v1.5 RSA-2048 decryption, SHA-256 / HMAC-SHA-256 key derivation,
//! AES-128-CBC entry decryption, and the AES-XTS (4096-byte sector) scheme
//! used for the PFS image.

use std::sync::OnceLock;

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use num_bigint_dig::BigUint;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::keys::{self, RsaComponents};

struct RsaKey {
    modulus: BigUint,
    public_exponent: BigUint,
    private_exponent: BigUint,
    prime1: BigUint,
    prime2: BigUint,
}

impl RsaKey {
    fn from_components(components: &RsaComponents) -> Self {
        Self {
            modulus: BigUint::from_bytes_be(components.modulus),
            public_exponent: BigUint::from_bytes_be(components.public_exponent),
            private_exponent: BigUint::from_bytes_be(components.private_exponent),
            prime1: BigUint::from_bytes_be(components.prime1),
            prime2: BigUint::from_bytes_be(components.prime2),
        }
    }
}

fn fake_key() -> &'static RsaKey {
    static KEY: OnceLock<RsaKey> = OnceLock::new();
    KEY.get_or_init(|| RsaKey::from_components(&keys::FAKE))
}

fn dk3_key() -> &'static RsaKey {
    static KEY: OnceLock<RsaKey> = OnceLock::new();
    KEY.get_or_init(|| RsaKey::from_components(&keys::PKG_DERIVED_KEY3))
}

/// Decrypts a 256-byte RSA block and returns the first 32 bytes of the
/// recovered message. `is_dk3` selects the PKG-derived-key-3 keyset, otherwise
/// the "fake" (npdrm) keyset is used.
pub(crate) fn rsa2048_decrypt(ciphertext: &[u8; 256], is_dk3: bool) -> Result<[u8; 32]> {
    let key = if is_dk3 { dk3_key() } else { fake_key() };
    let ciphertext = BigUint::from_bytes_be(ciphertext);
    if ciphertext >= key.modulus {
        return Err(Error::Crypto("RSA ciphertext is out of range".into()));
    }

    let decoded = ciphertext
        .modpow(&key.private_exponent, &key.modulus)
        .to_bytes_be();
    if decoded.len() > 256 {
        return Err(Error::Crypto("invalid RSA block size".into()));
    }
    let mut encoded = [0u8; 256];
    encoded[256 - decoded.len()..].copy_from_slice(&decoded);

    // PKCS#1 v1.5 encryption padding is 00 02 PS 00 M, with at least eight
    // non-zero padding bytes.
    if encoded[0] != 0 || encoded[1] != 2 {
        return Err(Error::Crypto("invalid PKCS#1 v1.5 padding".into()));
    }
    let separator = encoded[2..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| position + 2)
        .filter(|position| *position >= 10)
        .ok_or_else(|| Error::Crypto("invalid PKCS#1 v1.5 padding".into()))?;
    let message = &encoded[separator + 1..];
    let mut out = [0u8; 32];
    let n = message.len().min(out.len());
    out[..n].copy_from_slice(&message[..n]);
    Ok(out)
}

/// SHA-256 of a 64-byte input, truncated to the 32-byte IV/key result.
pub(crate) fn iv_key_hash256(input: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// AES-128-CBC decrypts `data` in place. The 32-byte `iv_key` supplies the IV
/// (bytes 0..16) and the key (bytes 16..32). `data` must be a multiple of 16.
pub(crate) fn aes_cbc128_decrypt(iv_key: &[u8; 32], data: &mut [u8]) {
    debug_assert_eq!(data.len() % 16, 0);
    let cipher = Aes128::new_from_slice(&iv_key[16..32]).expect("valid AES-128 key length");
    let mut previous = <[u8; 16]>::try_from(&iv_key[0..16]).unwrap();
    for chunk in data.chunks_exact_mut(16) {
        let ciphertext = <[u8; 16]>::try_from(&*chunk).unwrap();
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for (byte, prior) in chunk.iter_mut().zip(previous) {
            *byte ^= prior;
        }
        previous = ciphertext;
    }
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    debug_assert!(key.len() <= 64);
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(input);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Derives the PFS data and tweak keys from the EKPFS key and PFS seed.
/// Returns `(data_key, tweak_key)`.
pub(crate) fn pfs_gen_crypto_key(ekpfs: &[u8; 32], seed: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let mut input = [0u8; 20];
    input[0..4].copy_from_slice(&1u32.to_le_bytes());
    input[4..20].copy_from_slice(seed);

    let digest = hmac_sha256(ekpfs, &input);

    let mut tweak_key = [0u8; 16];
    let mut data_key = [0u8; 16];
    tweak_key.copy_from_slice(&digest[0..16]);
    data_key.copy_from_slice(&digest[16..32]);
    (data_key, tweak_key)
}

/// GF(2^128) multiply-by-alpha step of the XTS tweak (reduction poly 0x87).
fn xts_mult(tweak: &mut [u8; 16]) {
    let mut feedback = 0u8;
    for byte in tweak.iter_mut() {
        let carry = (*byte >> 7) & 1;
        *byte = (*byte << 1).wrapping_add(feedback);
        feedback = carry;
    }
    if feedback != 0 {
        tweak[0] ^= 0x87;
    }
}

/// AES-XTS-style decryption of a PFS image region using 4096-byte sectors.
///
/// `src` and `dst` must have the same length, a multiple of 0x1000. `sector`
/// is the index of the first 0x1000 sector within the region.
pub(crate) fn decrypt_pfs(
    data_key: &[u8; 16],
    tweak_key: &[u8; 16],
    src: &[u8],
    dst: &mut [u8],
    sector: u64,
) {
    debug_assert_eq!(src.len(), dst.len());
    debug_assert_eq!(src.len() % 0x1000, 0);

    let tweak_cipher = Aes128::new_from_slice(tweak_key).expect("valid AES-128 key length");
    let data_cipher = Aes128::new_from_slice(data_key).expect("valid AES-128 key length");

    let mut base = 0usize;
    while base < src.len() {
        let current_sector = sector + (base / 0x1000) as u64;

        let mut tweak = [0u8; 16];
        tweak[0..8].copy_from_slice(&current_sector.to_le_bytes());
        tweak_cipher.encrypt_block(GenericArray::from_mut_slice(&mut tweak));

        let mut offset = 0usize;
        while offset < 0x1000 {
            let at = base + offset;
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = src[at + i] ^ tweak[i];
            }
            data_cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
            for i in 0..16 {
                dst[at + i] = block[i] ^ tweak[i];
            }
            xts_mult(&mut tweak);
            offset += 16;
        }
        base += 0x1000;
    }
}

/// Validates that the embedded RSA key material parses successfully. Exposed so
/// callers can surface key problems eagerly rather than mid-extraction.
pub fn verify_embedded_keys() -> Result<()> {
    for key in [fake_key(), dk3_key()] {
        if &key.prime1 * &key.prime2 != key.modulus {
            return Err(Error::Crypto("RSA primes do not match modulus".into()));
        }
        let message = BigUint::from(2u8);
        let recovered = message
            .modpow(&key.public_exponent, &key.modulus)
            .modpow(&key.private_exponent, &key.modulus);
        if recovered != message {
            return Err(Error::Crypto("RSA exponents do not round-trip".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_keys_are_valid() {
        verify_embedded_keys().expect("embedded RSA keys should reconstruct");
    }

    #[test]
    fn xts_mult_shifts_left() {
        // 0x80 in byte 0 (bit 7) doubles to bit 8 (byte 1, bit 0).
        let mut t = [0u8; 16];
        t[0] = 0x80;
        xts_mult(&mut t);
        let mut expected = [0u8; 16];
        expected[1] = 0x01;
        assert_eq!(t, expected);
    }

    #[test]
    fn xts_mult_reduces_with_0x87() {
        // The top bit of the 128-bit value wraps with the XTS reduction poly.
        let mut t = [0u8; 16];
        t[15] = 0x80;
        xts_mult(&mut t);
        let mut expected = [0u8; 16];
        expected[0] = 0x87;
        assert_eq!(t, expected);
    }

    #[test]
    fn cbc_decrypt_inverts_encrypt() {
        let iv_key = [7u8; 32];
        let plain: Vec<u8> = (0..64u8).collect();

        let cipher = Aes128::new_from_slice(&iv_key[16..32]).unwrap();
        let mut previous = <[u8; 16]>::try_from(&iv_key[0..16]).unwrap();
        let mut buf = plain.clone();
        for chunk in buf.chunks_exact_mut(16) {
            for (byte, prior) in chunk.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
            previous.copy_from_slice(chunk);
        }
        aes_cbc128_decrypt(&iv_key, &mut buf);
        assert_eq!(buf, plain);
    }

    /// XTS encryption mirroring [`decrypt_pfs`], used only to prove the tweak
    /// sequencing is self-consistent.
    fn encrypt_pfs(data_key: &[u8; 16], tweak_key: &[u8; 16], buf: &mut [u8], sector: u64) {
        let tweak_cipher = Aes128::new_from_slice(tweak_key).unwrap();
        let data_cipher = Aes128::new_from_slice(data_key).unwrap();
        let mut base = 0;
        while base < buf.len() {
            let current_sector = sector + (base / 0x1000) as u64;
            let mut tweak = [0u8; 16];
            tweak[0..8].copy_from_slice(&current_sector.to_le_bytes());
            tweak_cipher.encrypt_block(GenericArray::from_mut_slice(&mut tweak));
            let mut offset = 0;
            while offset < 0x1000 {
                let at = base + offset;
                let mut block = [0u8; 16];
                for i in 0..16 {
                    block[i] = buf[at + i] ^ tweak[i];
                }
                data_cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
                for i in 0..16 {
                    buf[at + i] = block[i] ^ tweak[i];
                }
                xts_mult(&mut tweak);
                offset += 16;
            }
            base += 0x1000;
        }
    }

    #[test]
    fn pfs_xts_round_trips_across_sectors() {
        let data_key = [0x11u8; 16];
        let tweak_key = [0x22u8; 16];
        let plain: Vec<u8> = (0..0x2000u32).map(|x| x as u8).collect();

        let mut cipher = plain.clone();
        encrypt_pfs(&data_key, &tweak_key, &mut cipher, 0);
        assert_ne!(cipher, plain);

        let mut recovered = vec![0u8; plain.len()];
        decrypt_pfs(&data_key, &tweak_key, &cipher, &mut recovered, 0);
        assert_eq!(recovered, plain);
    }
}
