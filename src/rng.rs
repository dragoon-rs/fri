use std::mem::size_of;

use ark_ff::Field;
use rs_merkle::Hasher;

pub trait ReseedableRng {
    type Seed;

    fn reset(&mut self);
    fn reseed(&mut self, seed: Self::Seed);
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T;

    fn draw_alpha<F: Field>(&mut self) -> F {
        for _ in 0..1 {
            if let Some(elt) = self.next_bytes(|bytes| F::from_random_bytes(bytes)) {
                return elt;
            }
        }
        panic!("Failed to draw alpha after 1 attempts");
    }
    fn draw_positions(&mut self, number: usize, domain_size: usize) -> Vec<usize> {
        debug_assert!(
            domain_size.is_power_of_two(),
            "Domain size must be a power of two"
        );

        let mask = domain_size - 1;
        let mut positions = Vec::with_capacity(number);
        for _ in 0..number {
            let number = self.next_bytes(|bytes| {
                usize::from_le_bytes(bytes[0..size_of::<usize>()].try_into().unwrap())
            });
            positions.push(number & mask);
        }
        positions
    }
}

pub struct FriChallenger<H: Hasher> {
    seed: H::Hash,
    counter: usize,
}

impl<H: Hasher> Default for FriChallenger<H> {
    fn default() -> Self {
        Self {
            seed: H::hash(&[]),
            counter: 0,
        }
    }
}

impl<H: Hasher> ReseedableRng for FriChallenger<H>
where
    H::Hash: AsRef<[u8]>,
{
    type Seed = H::Hash;

    fn reset(&mut self) {
        self.seed = H::hash(&[]);
        self.counter = 0;
    }
    fn reseed(&mut self, seed: Self::Seed) {
        self.seed = H::concat_and_hash(&self.seed, Some(&seed));
        self.counter = 0;
    }
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        self.counter += 1;
        let hash = H::concat_and_hash(&self.seed, Some(&H::hash(&self.counter.to_le_bytes())));
        f(hash.as_ref())
    }
}

impl<'a, R> ReseedableRng for &'a mut R
where
    R: ReseedableRng + ?Sized,
{
    type Seed = R::Seed;
    fn reset(&mut self) {
        (**self).reset();
    }
    fn reseed(&mut self, seed: Self::Seed) {
        (**self).reseed(seed);
    }
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        (**self).next_bytes(f)
    }
}
