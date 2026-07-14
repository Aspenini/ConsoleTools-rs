use num_bigint::{BigInt, BigUint, Sign};
use sha1::{Digest, Sha1};

use crate::model::{Error, Header, KeyKind, Result, range};

const KEY_BYTES: usize = 256;
const MICROSOFT_MODULUS: [u8; KEY_BYTES] = [
    0xd3, 0xd7, 0x4e, 0xe5, 0x66, 0x3d, 0xd7, 0xe6, 0xc2, 0xd4, 0xa3, 0xa1, 0xf2, 0x17, 0x36, 0xd4,
    0x2e, 0x52, 0xf6, 0xd2, 0x02, 0x10, 0xf5, 0x64, 0x9c, 0x34, 0x7b, 0xff, 0xef, 0x7f, 0xc2, 0xee,
    0xbd, 0x05, 0x8b, 0xde, 0x79, 0xb4, 0x77, 0x8e, 0x5b, 0x8c, 0x14, 0x99, 0xe3, 0xae, 0xc6, 0x73,
    0x72, 0x73, 0xb5, 0xfb, 0x01, 0x5b, 0x58, 0x46, 0x6d, 0xfc, 0x8a, 0xd6, 0x95, 0xda, 0xed, 0x1b,
    0x2e, 0x2f, 0xa2, 0x29, 0xe1, 0x3f, 0xf1, 0xb9, 0x5b, 0x64, 0x51, 0x2e, 0xa2, 0xc0, 0xf7, 0xba,
    0xb3, 0x3e, 0x8a, 0x75, 0xff, 0x06, 0x92, 0x5c, 0x07, 0x26, 0x75, 0x79, 0x10, 0x5d, 0x47, 0xbe,
    0xd1, 0x6a, 0x52, 0x90, 0x0b, 0xae, 0x6a, 0x0b, 0x33, 0x44, 0x93, 0x5e, 0xf9, 0x9d, 0xfb, 0x15,
    0xd9, 0xa4, 0x1c, 0xcf, 0x6f, 0xe4, 0x71, 0x94, 0xbe, 0x13, 0x00, 0xa8, 0x52, 0xca, 0x07, 0xbd,
    0x27, 0x98, 0x01, 0xa1, 0x9e, 0x4f, 0xa3, 0xed, 0x9f, 0xa0, 0xaa, 0x73, 0xc4, 0x71, 0xf3, 0xe9,
    0x4e, 0x72, 0x42, 0x9c, 0xf0, 0x39, 0xce, 0xbe, 0x03, 0x76, 0xfa, 0x2b, 0x89, 0x14, 0x9a, 0x81,
    0x16, 0xc1, 0x80, 0x8c, 0x3e, 0x6b, 0xaa, 0x05, 0xec, 0x67, 0x5a, 0xcf, 0xa5, 0x70, 0xbd, 0x60,
    0x0c, 0xe8, 0x37, 0x9d, 0xeb, 0xf4, 0x52, 0xea, 0x4e, 0x60, 0x9f, 0xe4, 0x69, 0xcf, 0x52, 0xdb,
    0x68, 0xf5, 0x11, 0xcb, 0x57, 0x8f, 0x9d, 0xa1, 0x38, 0x0a, 0x0c, 0x47, 0x1b, 0xb4, 0x6c, 0x5a,
    0x53, 0x6e, 0x26, 0x98, 0xf1, 0x88, 0xae, 0x7c, 0x96, 0xbc, 0xf6, 0xbf, 0xb0, 0x47, 0x9a, 0x8d,
    0xe4, 0xb3, 0xe2, 0x98, 0x85, 0x61, 0xb1, 0xca, 0x5f, 0xf7, 0x98, 0x51, 0x2d, 0x83, 0x81, 0x76,
    0x0c, 0x88, 0xba, 0xd4, 0xc2, 0xd5, 0x3c, 0x14, 0xc7, 0x72, 0xda, 0x7e, 0xbd, 0x1b, 0x4b, 0xa4,
];

const PKCS1_SHA1_PREFIX_A_REVERSED: [u8; 15] = [
    0x14, 0x04, 0x00, 0x05, 0x1a, 0x02, 0x03, 0x0e, 0x2b, 0x05, 0x06, 0x09, 0x30, 0x21, 0x30,
];
const PKCS1_SHA1_PREFIX_B_REVERSED: [u8; 13] = [
    0x14, 0x04, 0x1a, 0x02, 0x03, 0x0e, 0x2b, 0x05, 0x06, 0x07, 0x30, 0x1f, 0x30,
];

struct RsaKey {
    exponent: u32,
    modulus: [u8; KEY_BYTES],
    private_exponent: Option<[u8; KEY_BYTES]>,
}

pub(crate) fn xbe_sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
    hasher.update(length.to_le_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

pub(crate) fn verify_signature(data: &[u8], header: &Header, kind: KeyKind) -> Result<bool> {
    let digest = header_digest(data, header)?;
    let key = key(kind);
    let signature = BigUint::from_bytes_le(&header.signature);
    let modulus = BigUint::from_bytes_le(&key.modulus);
    if signature >= modulus {
        return Ok(false);
    }
    let decoded = signature.modpow(&BigUint::from(key.exponent), &modulus);
    let mut bytes = decoded.to_bytes_le();
    bytes.resize(KEY_BYTES, 0);
    Ok(valid_padding(&bytes, &digest))
}

pub(crate) fn sign_header(data: &[u8], header: &Header, kind: KeyKind) -> Result<[u8; KEY_BYTES]> {
    let digest = header_digest(data, header)?;
    let key = key(kind);
    let private = key.private_exponent.ok_or(Error::MissingPrivateKey)?;
    let mut encoded = [0xff; KEY_BYTES];
    for (target, source) in encoded[..20].iter_mut().zip(digest.iter().rev()) {
        *target = *source;
    }
    encoded[20] = 0;
    encoded[254] = 1;
    encoded[255] = 0;
    let signature = BigUint::from_bytes_le(&encoded).modpow(
        &BigUint::from_bytes_le(&private),
        &BigUint::from_bytes_le(&key.modulus),
    );
    let bytes = signature.to_bytes_le();
    let mut output = [0; KEY_BYTES];
    let length = bytes.len().min(KEY_BYTES);
    output[..length].copy_from_slice(&bytes[..length]);
    Ok(output)
}

pub(crate) fn entry_xor_key(kind: KeyKind) -> u32 {
    xor_word(kind, 0x20) ^ xor_word(kind, 0x24)
}

pub(crate) fn thunk_xor_key(kind: KeyKind) -> u32 {
    xor_word(kind, 0x21) ^ xor_word(kind, 0x22)
}

pub(crate) fn xor_patch_delta(kind: KeyKind) -> (u32, u32) {
    (
        entry_xor_key(KeyKind::Microsoft) ^ entry_xor_key(kind),
        thunk_xor_key(KeyKind::Microsoft) ^ thunk_xor_key(kind),
    )
}

fn header_digest(data: &[u8], header: &Header) -> Result<[u8; 20]> {
    let header_size = usize::try_from(header.header_size).map_err(|_| Error::InvalidValue {
        context: "header size",
        value: header.header_size.into(),
    })?;
    let size = header_size.checked_sub(0x104).ok_or(Error::InvalidValue {
        context: "header size",
        value: header.header_size.into(),
    })?;
    Ok(xbe_sha1(range(data, 0x104, size, "signed header region")?))
}

fn valid_padding(decoded: &[u8], digest: &[u8; 20]) -> bool {
    if decoded.len() != KEY_BYTES || decoded[..20].iter().ne(digest.iter().rev()) {
        return false;
    }
    let zero = if decoded[20..].starts_with(&PKCS1_SHA1_PREFIX_A_REVERSED) {
        20 + PKCS1_SHA1_PREFIX_A_REVERSED.len()
    } else if decoded[20..].starts_with(&PKCS1_SHA1_PREFIX_B_REVERSED) {
        20 + PKCS1_SHA1_PREFIX_B_REVERSED.len()
    } else {
        20
    };
    decoded[zero] == 0
        && decoded[254] == 1
        && decoded[255] == 0
        && decoded[zero + 1..254].iter().all(|byte| *byte == 0xff)
}

fn key(kind: KeyKind) -> RsaKey {
    match kind {
        KeyKind::Microsoft => RsaKey {
            exponent: 65_537,
            modulus: MICROSOFT_MODULUS,
            private_exponent: None,
        },
        KeyKind::Test => {
            let mut private = [0; KEY_BYTES];
            private[0] = 1;
            RsaKey {
                exponent: 1,
                modulus: MICROSOFT_MODULUS,
                private_exponent: Some(private),
            }
        }
        KeyKind::Habibi => habibi_key(),
    }
}

fn habibi_key() -> RsaKey {
    let mut modulus = MICROSOFT_MODULUS;
    modulus[252..].copy_from_slice(&0x899c_906bu32.to_le_bytes());
    let modulus_number = BigUint::from_bytes_le(&modulus);
    let phi = (modulus_number / 3u8 - 1u8) * 2u8;
    let private = modular_inverse(&BigUint::from(65_537u32), &phi)
        .expect("historical Habibi key exponent is invertible");
    let bytes = private.to_bytes_le();
    let mut private_exponent = [0; KEY_BYTES];
    private_exponent[..bytes.len()].copy_from_slice(&bytes);
    RsaKey {
        exponent: 65_537,
        modulus,
        private_exponent: Some(private_exponent),
    }
}

fn modular_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let mut old_r = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let mut r = BigInt::from_biguint(Sign::Plus, value.clone());
    let mut old_t = BigInt::from(0);
    let mut t = BigInt::from(1);
    while r != BigInt::from(0) {
        let quotient = &old_r / &r;
        (old_r, r) = (r.clone(), old_r - &quotient * &r);
        (old_t, t) = (t.clone(), old_t - quotient * &t);
    }
    if old_r != BigInt::from(1) {
        return None;
    }
    let modulus_signed = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let normalized = ((old_t % &modulus_signed) + &modulus_signed) % &modulus_signed;
    normalized.to_biguint()
}

fn xor_word(kind: KeyKind, index: usize) -> u32 {
    let key = key(kind);
    let mut blob = [0; 20 + KEY_BYTES];
    blob[..4].copy_from_slice(b"RSA1");
    blob[4..8].copy_from_slice(&0x108u32.to_le_bytes());
    blob[8..12].copy_from_slice(&2048u32.to_le_bytes());
    blob[12..16].copy_from_slice(&255u32.to_le_bytes());
    blob[16..20].copy_from_slice(&key.exponent.to_le_bytes());
    blob[20..].copy_from_slice(&key.modulus);
    let offset = index * 4;
    u32::from_le_bytes(
        blob[offset..offset + 4]
            .try_into()
            .expect("key word in range"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_xors_match_historical_constants() {
        assert_eq!(entry_xor_key(KeyKind::Microsoft), 0xa8fc_57ab);
        assert_eq!(thunk_xor_key(KeyKind::Microsoft), 0x5b6d_40b6);
    }

    #[test]
    fn raw_padding_round_trips_with_test_key() {
        let digest = [0x42; 20];
        let mut encoded = [0xff; KEY_BYTES];
        for (target, source) in encoded[..20].iter_mut().zip(digest.iter().rev()) {
            *target = *source;
        }
        encoded[20] = 0;
        encoded[254] = 1;
        encoded[255] = 0;
        assert!(valid_padding(&encoded, &digest));
    }
}
