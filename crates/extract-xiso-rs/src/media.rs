//! Automatic .xbe media-enable patching.
//!
//! Xbox executables check the disc media type; images built for DVD-R/W etc.
//! are rejected unless the check is patched. The tool searches .xbe files
//! for the 8-byte check sequence and rewrites its final byte with a short
//! jump (0xEB), exactly like the original C implementation.

use crate::format::{MEDIA_ENABLE_BYTE, MEDIA_ENABLE_BYTE_POS, MEDIA_ENABLE_PATTERN};

/// Patch every occurrence of the media-check pattern in `buf`.
/// Returns the number of patches applied.
///
/// ```
/// use extract_xiso::format::{MEDIA_ENABLE_BYTE, MEDIA_ENABLE_PATTERN};
/// use extract_xiso::media::patch_media_enable;
///
/// let mut buf = MEDIA_ENABLE_PATTERN.to_vec();
/// assert_eq!(patch_media_enable(&mut buf), 1);
/// assert_eq!(buf[7], MEDIA_ENABLE_BYTE);
/// ```
pub fn patch_media_enable(buf: &mut [u8]) -> usize {
    let pat = MEDIA_ENABLE_PATTERN;
    let mut patched = 0;
    let mut i = 0;
    while i + pat.len() <= buf.len() {
        if buf[i] == pat[0] && buf[i..i + pat.len()] == pat[..] {
            buf[i + MEDIA_ENABLE_BYTE_POS] = MEDIA_ENABLE_BYTE;
            patched += 1;
            i += pat.len();
        } else {
            i += 1;
        }
    }
    patched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_all_occurrences() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"leading");
        buf.extend_from_slice(MEDIA_ENABLE_PATTERN);
        buf.extend_from_slice(b"middle");
        buf.extend_from_slice(MEDIA_ENABLE_PATTERN);
        assert_eq!(patch_media_enable(&mut buf), 2);
        assert_eq!(buf[7 + MEDIA_ENABLE_BYTE_POS], MEDIA_ENABLE_BYTE);
        assert_eq!(buf[7 + 8 + 6 + MEDIA_ENABLE_BYTE_POS], MEDIA_ENABLE_BYTE);
    }

    #[test]
    fn leaves_other_data_alone() {
        let mut buf = vec![0u8; 64];
        assert_eq!(patch_media_enable(&mut buf), 0);
        assert!(buf.iter().all(|&b| b == 0));
    }
}
