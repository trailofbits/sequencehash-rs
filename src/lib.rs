mod sequencefunc;
mod common;

use crypto_common::BlockSizeUser;
pub use crypto_common::InvalidLength;
use digest::Digest;

pub struct SequenceHash<T> (sequencefunc::SequenceFunc<T>);
pub struct SequenceMAC<T> (sequencefunc::SequenceFunc<T>);


impl<T: BlockSizeUser + Clone + Digest> SequenceMAC<T> {
    /// Creates a SequenceMAC from `key`.
    ///
    /// Returns [`InvalidLength`] if the key is shorter than 32 bytes. Keys of
    /// 32 bytes or more are accepted.
    pub fn new(key: &impl AsRef<[u8]>) -> Result<Self, InvalidLength> {
        if key.as_ref().len() < common::MIN_KEY_LEN {
            return Err(InvalidLength);
        }

        Ok(Self(sequencefunc::SequenceFunc::new(common::FUNC_ID_SEQMAC, &key.as_ref())))
    }

    pub fn add(&mut self, data: &impl AsRef<[u8]>) {
        self.0.add(data);
    }

    pub fn reset(&mut self) {
        self.0.reset();
    }

    pub fn result_with_customizer(&self, customizer: &impl AsRef<[u8]>) -> Vec<u8> {
        self.0.result_with_customizer(customizer)
    }

    pub fn result(&self) -> Vec<u8> {
        self.0.result()
    }

    pub fn output_size(&self) -> usize {
        self.0.output_size()
    }

    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

impl<T: BlockSizeUser + Clone + Digest> SequenceHash<T> {
    pub fn new() -> Self {
        Self(sequencefunc::SequenceFunc::new(common::FUNC_ID_SEQHSH, &[]))
    }

    pub fn add(&mut self, data: &impl AsRef<[u8]>) {
        self.0.add(data);
    }

    pub fn reset(&mut self) {
        self.0.reset();
    }

    pub fn result_with_customizer(&self, customizer: &impl AsRef<[u8]>) -> Vec<u8> {
        self.0.result_with_customizer(customizer)
    }

    pub fn result(&self) -> Vec<u8> {
        self.0.result()
    }

    pub fn output_size(&self) -> usize {
        self.0.output_size()
    }

    pub fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2;

    #[test]
    fn test_kat_hash() {
        let expected: Vec<u8> = vec![
            0xfe, 0x55, 0x0c, 0x16, 0x3f, 0x7c, 0xe3, 0xe8,
            0xf6, 0x36, 0xca, 0x87, 0x70, 0x33, 0x3c, 0x4c,
            0xe3, 0x3a, 0x1d, 0x84, 0x24, 0xb4, 0xf3, 0x83,
            0x03, 0x6d, 0x42, 0x49, 0x29, 0x11, 0x11, 0x44,
        ];
        let input0: Vec<u8> = vec![];
        let input1: Vec<u8> = vec![0x01];
        let input2: Vec<u8> = vec![0x02, 0x02];
        let input3: Vec<u8> = vec![0x03, 0x03, 0x03];

        let mut hasher = SequenceHash::<sha2::Sha256>::new();
        hasher.add(&input0);
        hasher.add(&input1);
        hasher.add(&input2);
        hasher.add(&input3);

        let hash_output = hasher.result();
        assert_eq!(hash_output, expected);
    }

    #[test]
    fn test_kat_mac() {
        let key: Vec<u8> = vec![
            0x27, 0xec, 0xe6, 0x76, 0x4c, 0x77, 0xeb, 0x17,
            0xe2, 0x8a, 0x40, 0x31, 0x87, 0x81, 0x98, 0xf3,
            0x7c, 0xe9, 0x52, 0x07, 0x20, 0x5f, 0xba, 0x86,
            0x71, 0x39, 0x0c, 0x8d, 0x74, 0x49, 0xdc, 0x91
        ];
        let customizer: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];

        let expected: Vec<u8> = vec![
            0x48, 0x4a, 0xd1, 0x23, 0xab, 0x6f, 0x1f, 0xea,
            0x03, 0xac, 0x9a, 0xe7, 0x65, 0xa3, 0x8b, 0xd3,
            0x41, 0x28, 0x36, 0x7f, 0x40, 0x8e, 0xad, 0xa7,
            0xff, 0x8c, 0x21, 0xb3, 0xcd, 0x85, 0x15, 0xc3
        ];

        let input0: Vec<u8> = vec![
            0x74, 0xae, 0xe8, 0x3f, 0x30, 0xdb, 0x3f, 0xd8,
            0x8d, 0x6e, 0x31, 0xad, 0x41, 0x71, 0x0c, 0xb8,
            0xd9, 0xa5, 0xdd, 0x01, 0xaa, 0xd1, 0xd1
        ];
        let input1: Vec<u8> = vec![
            0xf1, 0xed, 0x6e, 0x58, 0xd4, 0x42, 0x90, 0x3e,
            0x34, 0x57, 0x15, 0x44, 0xa8, 0xaf, 0x4f, 0x49,
            0xe8, 0x67, 0x90, 0x41, 0x79, 0x16, 0xf5, 0x38,
            0x74, 0x69, 0x11, 0xed, 0xbb, 0xd3, 0x4f, 0xb9
        ];
        let input2: Vec<u8> = vec![
            0xbd, 0x12, 0x16, 0x35, 0xc5, 0xc7, 0x32
        ];

        let mut hasher = SequenceMAC::<sha2::Sha256>::new(&key).unwrap();
        hasher.add(&input0);
        hasher.add(&input1);
        hasher.add(&input2);

        let hash_output = hasher.result_with_customizer(&customizer);
        assert_eq!(hash_output, expected);
    }

    #[test]
    fn test_mac_block_size() {
        let key: Vec<u8> = vec![0x00u8; 32];
        let mac = SequenceMAC::<sha2::Sha256>::new(&key).unwrap();
        assert_eq!(mac.block_size(), sha2::Sha256::block_size());
    }

    #[test]
    fn test_mac_rejects_short_key() {
        for len in [0usize, 1, 31] {
            let key = vec![0x00u8; len];
            assert!(
                matches!(
                    SequenceMAC::<sha2::Sha256>::new(&key),
                    Err(crate::InvalidLength)
                ),
                "len {len}"
            );
        }
    }

    #[test]
    fn test_mac_accepts_min_and_longer_key() {
        for len in [32usize, 33, 64] {
            let key = vec![0x00u8; len];
            assert!(SequenceMAC::<sha2::Sha256>::new(&key).is_ok(), "len {len}");
        }
    }

    #[test]
    fn test_hash_block_size() {
        let hasher = SequenceHash::<sha2::Sha256>::new();
        assert_eq!(hasher.block_size(), sha2::Sha256::block_size());
    }

    #[test]
    fn test_mac_output_size() {
        let key: Vec<u8> = vec![0x00u8; 32];
        let mac = SequenceMAC::<sha2::Sha256>::new(&key).unwrap();
        assert_eq!(mac.output_size(), sha2::Sha256::output_size());
    }

    #[test]
    fn test_hash_output_size() {
        let hasher = SequenceHash::<sha2::Sha256>::new();
        assert_eq!(hasher.output_size(), sha2::Sha256::output_size());
    }
}