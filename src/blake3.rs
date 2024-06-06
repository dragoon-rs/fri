use rs_merkle::Hasher;

/// Blake3-256 implementation of the [`rs_merkle::Hasher`] trait.
///
/// See documentation of crate [`sha3`].
#[derive(Clone, Copy, Debug)]
pub struct Blake3;

impl Hasher for Blake3 {
    type Hash = [u8; blake3::OUT_LEN];

    fn hash(data: &[u8]) -> Self::Hash {
        blake3::hash(data).into()
    }
}
