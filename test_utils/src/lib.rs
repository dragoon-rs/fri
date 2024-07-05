//! Code shared between tests and benches

use ark_ff::{Fp128, MontBackend, MontConfig};
use rand::{
    distributions::{Distribution, Standard},
    thread_rng, Rng,
};

pub const NUMBER_OF_POLYNOMIALS: usize = 10;
pub const POLY_COEFFS_LEN: usize = 4096;
pub const BLOWUP_FACTOR: usize = 4;
pub const NUM_QUERIES: usize = 32;

pub const DOMAIN_SIZE: usize = (POLY_COEFFS_LEN * BLOWUP_FACTOR).next_power_of_two();

/// Matches `BaseElement` from winterfell
#[derive(MontConfig)]
#[modulus = "340282366920938463463374557953744961537"]
#[generator = "3"]
pub struct Test;
/// A prime, fft-friendly field isomorph to [`winter_math::fields::f128::BaseElement`].
pub type Fq = Fp128<MontBackend<Test, 2>>;

pub fn random_file<F: Clone>(k: usize, nb_polynomials: usize) -> Vec<Vec<F>>
where
    Standard: Distribution<F>,
{
    let nb_items = k * nb_polynomials;
    let mut rng = thread_rng();
    (0..nb_items)
        .map(|_| rng.gen())
        .collect::<Vec<_>>()
        .chunks_exact(k)
        .map(<[F]>::to_vec)
        .collect()
}

#[macro_export]
macro_rules! do_for_multiple_folding_factors {
    ($factor: ident = $($factors: literal),* => $action: block) => {
        {
            $({
                const $factor: usize = $factors;
                $action;
            })*
        }
    };
}
