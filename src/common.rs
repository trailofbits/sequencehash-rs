use crypto_common::BlockSizeUser;
use digest::Digest;
use zeroize::{Zeroize, Zeroizing};

// Function identifiers: currently only defined for SequenceHash and SequenceMAC
pub const FUNC_ID_SEQMAC: u128 = 1;
pub const FUNC_ID_SEQHSH: u128 = 2;

// Key derivation tweaks
pub const TWEAK_KEY_INNER: u8 = 0x55;
pub const TWEAK_KEY_OUTER: u8 = 0xaa;

// Header block starting values
pub const INIT_INNER: &str = "SEQHSH_I";
pub const INIT_OUTER: &str = "SEQHSH_O";

// Header sizes
pub const OUTER_HEADER_SIZE: usize = 56;
pub const INNER_HEADER_SIZE: usize = 40;

// SequenceMAC specification says keys must be at least 32 bytes
pub const MIN_KEY_LEN: usize = 32;


// Encoding function
pub fn encode_int_msbf(x: u128) -> [u8; 16] {
    x.to_be_bytes()
}

pub fn encode_int_lsbf(x: u128) -> [u8; 16] {
    x.to_le_bytes()
}

pub fn pad(data: impl AsRef<[u8]>, block_size: usize) -> Vec<u8> {
    let mut block_count = data.as_ref().len().div_ceil(block_size);
    if block_count == 0 {
        block_count = 1;
    }
    let mut padded: Vec<u8> = vec![0x00u8; block_size * block_count];
    let end = data.as_ref().len();
    padded[0..end].copy_from_slice(data.as_ref());

    padded
}

/// Derives a padded, tweaked block from `value` (a key or a customizer).
///
/// The SequenceHash specification says implementations "SHOULD zeroize `K`,
/// `K_I`, and `K_O` when no longer needed for computations", and asks for any
/// deviation from a SHOULD to be documented. This is best effort:
///
/// - The returned block is `Zeroizing`, so it is wiped when dropped. This
///   covers `K_I` and `K_O`.
/// - The hash of a key longer than the block size is wiped before returning.
/// - No other copy of `value` is made. (The old code made two, via
///   `Vec::from` and `pad`.)
/// - `K` itself belongs to the caller, who should wipe it.
/// - The keyed hash states in `SequenceFunc` hold key-derived data but can't
///   be wiped: `digest` 0.10 hash types don't implement `Zeroize`.
pub fn derive_value<T: BlockSizeUser + Digest>(value: &[u8], tweak: u8) -> Zeroizing<Vec<u8>> {
    let block_size = T::block_size();
    let mut reduced = None;
    let source: &[u8] = if value.len() > block_size {
        &reduced.insert(T::digest(value))[..]
    } else {
        value
    };

    let block_count = source.len().div_ceil(block_size).max(1);
    let mut derived = Zeroizing::new(vec![0x00u8; block_size * block_count]);
    derived[..source.len()].copy_from_slice(source);
    derived[0] ^= tweak;

    if let Some(digest) = reduced.as_mut() {
        digest.as_mut_slice().zeroize();
    }
    derived
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    // The derivation before zeroization was added, kept as a reference.
    fn derive_value_reference<T: BlockSizeUser + Digest>(value: &[u8], tweak: u8) -> Vec<u8> {
        let mut derived = if value.len() > T::block_size() { T::digest(value).to_vec() } else { Vec::from(value) };
        derived = pad(&derived, T::block_size());
        derived[0] ^= tweak;
        derived
    }

    fn check<T: BlockSizeUser + Digest>() {
        let bs = T::block_size();
        for len in 0..=(3 * bs) {
            let value: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
            for tweak in [0x00, TWEAK_KEY_INNER, TWEAK_KEY_OUTER] {
                let derived: Zeroizing<Vec<u8>> = derive_value::<T>(&value, tweak);
                assert_eq!(*derived, derive_value_reference::<T>(&value, tweak), "len {len} tweak {tweak}");
            }
        }
    }

    #[test]
    fn test_derive_value_unchanged() {
        check::<sha2::Sha256>();
        check::<sha2::Sha512>();
    }
}
