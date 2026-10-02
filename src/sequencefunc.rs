use crypto_common::BlockSizeUser;
use digest::Digest;

use crate::common;

#[derive(Clone)]
pub struct SequenceFunc<T> {
    inner: T,
    outer: T,
    inner_init: T,
    outer_init: T,
    key_len: u128,
    func_id: u128,
    count: u128,
}

impl<T: BlockSizeUser + Clone + Digest> SequenceFunc<T> {
    fn get_inner_header(func_id: u128, key_len: u128) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::with_capacity(common::INNER_HEADER_SIZE);
        header.extend_from_slice(common::INIT_INNER.as_bytes());
        header.extend_from_slice(&common::encode_int_msbf(func_id));
        header.extend_from_slice(&common::encode_int_msbf(key_len));
        common::pad(header, T::block_size())
    }

    fn get_outer_header(&self, customizer: &impl AsRef<[u8]>) -> Vec<u8> {
        let mut header: Vec<u8> = Vec::with_capacity(common::OUTER_HEADER_SIZE);
        header.extend_from_slice(common::INIT_OUTER.as_bytes());
        header.extend_from_slice(&common::encode_int_msbf(self.func_id));
        header.extend_from_slice(&common::encode_int_msbf(customizer.as_ref().len() as u128));
        header.extend_from_slice(&common::encode_int_msbf(self.key_len));
        common::pad(header, T::block_size())
    }

    pub fn new(fn_id: u128, key: &impl AsRef<[u8]>) -> Self {
        let key_len = key.as_ref().len() as u128;

        // First, set up the inner hash: derive the inner key, compute the header
        let key_inner = common::derive_value::<T>(key.as_ref(), common::TWEAK_KEY_INNER);
        let hdr_inner = Self::get_inner_header(fn_id, key_len);
        let mut inner_hash = T::new();
        inner_hash.update(&key_inner);
        inner_hash.update(&hdr_inner);

        // Then set up the outer hash
        let key_outer = common::derive_value::<T>(key.as_ref(), common::TWEAK_KEY_OUTER);
        let mut outer_hash = T::new();
        outer_hash.update(&key_outer);

        SequenceFunc {
            inner: inner_hash.clone(),
            outer: outer_hash.clone(),
            inner_init: inner_hash.clone(),
            outer_init: outer_hash.clone(),
            key_len: key_len,
            func_id: fn_id,
            count: 0u128,
        }
    }

    pub fn add(&mut self, data: &impl AsRef<[u8]>) {
        if self.count == u128::MAX {
            panic!("Too many elements hashed")
        }
        self.inner.update(data.as_ref());
        self.inner.update(&common::encode_int_lsbf(data.as_ref().len() as u128));
        self.count += 1u128;
    }

    pub fn result_with_customizer(&self, customizer: &impl AsRef<[u8]>) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(<T as Digest>::output_size());

        let inner_hash = self.inner.clone().finalize();

        let outer_header = self.get_outer_header(&customizer.as_ref());
        let customizer_block = common::derive_value::<T>(&customizer.as_ref(), 0);

        let mut outer_copy = self.outer.clone();
        outer_copy.update(outer_header);
        outer_copy.update(customizer_block);
        outer_copy.update(&common::encode_int_msbf(self.count));
        outer_copy.update(&common::encode_int_msbf(<T as Digest>::output_size() as u128));
        outer_copy.update(&inner_hash);

        result.extend_from_slice(&outer_copy.finalize());
        result
    }

    pub fn result(&self) -> Vec<u8> {
        self.result_with_customizer(&[])
    }

    pub fn reset(&mut self) {
        self.inner = self.inner_init.clone();
        self.outer = self.outer_init.clone();
        self.count = 0;
    }

    pub fn block_size(&self) -> usize {
        <T as BlockSizeUser>::block_size()
    }

    pub fn output_size(&self) -> usize {
        <T as Digest>::output_size()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_kat_hash() {

    }
}