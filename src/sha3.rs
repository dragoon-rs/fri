use rs_merkle::Hasher;
use sha3::{digest::FixedOutput, Digest};

/// Sha3-256 implementation of the [`rs_merkle::Hasher`] trait.
/// 
/// See documentation of crate [`sha3`].
#[derive(Clone, Copy, Debug)]
pub struct Sha3_256;

impl Hasher for Sha3_256 {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}

/// Sha3-512 implementation of the [`rs_merkle::Hasher`] trait.
/// 
/// See documentation of crate [`sha3`].
#[derive(Clone, Copy, Debug)]
pub struct Sha3_512;

impl Hasher for Sha3_512 {
    type Hash = [u8; 64];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(data);
        <[u8; 64]>::from(hasher.finalize_fixed())
    }
}