use crypto_common::BlockSizeUser;
use digest::Digest;

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

pub fn derive_value<T: BlockSizeUser + Digest>(value: &[u8], tweak: u8) -> Vec<u8> {
    let mut derived = if value.len() > T::block_size() { T::digest(value).to_vec() } else { Vec::from(value) };
    derived = pad(&derived, T::block_size());
    derived[0] ^= tweak;
    derived
}