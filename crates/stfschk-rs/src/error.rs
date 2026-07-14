use std::{error, fmt, io};

/// Errors produced while reading or parsing an STFS package.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidMagic([u8; 4]),
    UnsupportedSvod,
    NotStfs,
    InvalidDescriptorLength(u8),
    Truncated {
        context: &'static str,
        offset: u64,
        needed: usize,
        available: usize,
    },
    InvalidBlock(u32),
    BlockChainCycle(u32),
    ArithmeticOverflow(&'static str),
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::InvalidMagic(magic) => write!(
                f,
                "file has invalid header magic {:02X}{:02X}{:02X}{:02X}",
                magic[0], magic[1], magic[2], magic[3]
            ),
            Self::UnsupportedSvod => f.write_str("package contains unsupported SVOD filesystem"),
            Self::NotStfs => f.write_str("package does not contain an STFS filesystem"),
            Self::InvalidDescriptorLength(length) => {
                write!(f, "file has invalid descriptor length 0x{length:02X}")
            }
            Self::Truncated {
                context,
                offset,
                needed,
                available,
            } => write!(
                f,
                "truncated {context} at 0x{offset:X}: need {needed} bytes, have {available}"
            ),
            Self::InvalidBlock(block) => write!(f, "data block 0x{block:X} is out of range"),
            Self::BlockChainCycle(block) => {
                write!(f, "block chain contains a cycle at block 0x{block:X}")
            }
            Self::ArithmeticOverflow(context) => {
                write!(f, "integer overflow while computing {context}")
            }
            Self::Crypto(message) => write!(f, "cryptographic error: {message}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub(crate) fn slice<'a>(
    data: &'a [u8],
    offset: usize,
    length: usize,
    context: &'static str,
) -> Result<&'a [u8], Error> {
    let end = offset
        .checked_add(length)
        .ok_or(Error::ArithmeticOverflow(context))?;
    data.get(offset..end).ok_or(Error::Truncated {
        context,
        offset: offset as u64,
        needed: length,
        available: data.len().saturating_sub(offset),
    })
}
