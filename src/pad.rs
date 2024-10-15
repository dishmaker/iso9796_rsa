//! Special handling for converting the BigUint to u8 vectors
//!
//! based on rsa crate

use eyre::eyre;
use rsa::BigUint;
use zeroize::Zeroizing;

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[inline]
pub fn uint_to_be_pad(input: BigUint, padded_len: usize) -> eyre::Result<Vec<u8>> {
    left_pad(&input.to_bytes_be(), padded_len)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
#[inline]
pub fn uint_to_zeroizing_be_pad(input: BigUint, padded_len: usize) -> eyre::Result<Vec<u8>> {
    let m = Zeroizing::new(input);
    let m = Zeroizing::new(m.to_bytes_be());
    left_pad(&m, padded_len)
}
/// Returns a new vector of the given length, with 0s left padded.
#[inline]
fn left_pad(input: &[u8], padded_len: usize) -> eyre::Result<Vec<u8>> {
    if input.len() > padded_len {
        return Err(eyre!("invalid pad len"));
    }

    let mut out = vec![0u8; padded_len];
    out[padded_len - input.len()..].copy_from_slice(input);
    Ok(out)
}
