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

/// Matches [`winter_math::fields::f128::BaseElement`]
#[derive(MontConfig)]
#[modulus = "340282366920938463463374557953744961537"]
#[generator = "3"]
pub struct Fp128Config;
/// A prime, fft-friendly field isomorph to [`winter_math::fields::f128::BaseElement`](https://github.com/facebook/winterfell/blob/9f21cf426cae080f8871ec2043573ce5652dad72/math/src/field/f128/mod.rs#L40)
pub type Fq = Fp128<MontBackend<Fp128Config, 2>>;

/// Sample a _random file_ pre-arranged in an $m \ times k$ matrix of elements of $\mathbb{F}$
///
/// > **Note**
/// >
/// > - $k$ is the FEC parameter
/// > - $m$ is the number of polynomials which is related to $k$ and the size of the possibly
/// >   padded file by
/// >       $$s = k \times m \ times F$$
/// >   where $s$ is the size of the padded file and $F$ is the size, in bytes, of an element of
/// >   $\mathbb{F}$
pub fn random_file<F: Clone>(k: usize, m: usize) -> Vec<Vec<F>>
where
    Standard: Distribution<F>,
{
    let nb_items = k * m;
    let mut rng = thread_rng();
    (0..nb_items)
        .map(|_| rng.gen())
        .collect::<Vec<_>>()
        .chunks_exact(k)
        .map(<[F]>::to_vec)
        .collect()
}

/// allows to run a code snippet with a "_varying_" constant
///
/// this is especially useful in tests for functions that require a constant value.
///
/// ## example
/// the following macro invocation
/// ```rust
/// do_for_multiple_folding_factors!(FACTOR = 2, 4, 8, 16 => {
///   // some arbitrary code involving the `FACTOR` constant
/// });
/// ```
/// will be expanded to
/// ```rust
/// const FACTOR: usize = 2;
/// // the code
/// const FACTOR: usize = 4;
/// // the code
/// const FACTOR: usize = 8;
/// // the code
/// const FACTOR: usize = 16;
/// // the code
/// ```
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
