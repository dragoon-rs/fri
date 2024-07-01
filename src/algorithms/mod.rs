//! This module contains implementations of trait [`rs_merkle::Hasher`] for other algorithms
//! than [`Sha2-256`](`rs_merkle::algorithms::Sha256`) and [`Sha2-384`](`rs_merkle::algorithms::Sha384`),
//! which are already provided by [`rs_merkle`].
//! 
//! These implementations are opt-in and only provided if the corresponding features are enabled.

#[cfg(any(test, feature = "blake3"))]
pub mod blake3;
#[cfg(any(test, feature = "blake3"))]
pub use blake3::Blake3;

#[cfg(feature = "sha3")]
pub mod sha3;
#[cfg(feature = "sha3")]
pub use sha3::{Sha3_256, Sha3_512};
