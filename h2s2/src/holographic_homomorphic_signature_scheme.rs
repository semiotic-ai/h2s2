use ark_std::UniformRand;
use ark_std::Zero;
use std::error::Error;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_std::{marker::PhantomData, rand::Rng};
use digest::Digest;
use std::ops::MulAssign;

pub trait HolographicHomomorphicSignatureScheme<P: Pairing, D: Digest + Send + Sync> {
    type Parameters;
    type PublicKey;
    type SecretKey;
    type Signature;
    type Message;
    type Weight;

    /// Generate one G2 element and `n` G1 elements
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Box<dyn Error>>;

    /// Generate hash aggregate (H_a) with `tag` and `n` lanes
    fn precompute(tag: &[u8], n: usize) -> Result<P::G1, Box<dyn Error>>;

    /// Generate private and public receipt keys using `pp` parameters from `setup`
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Box<dyn Error>>;

    /// Sign `message` with `tag` at `index`
    fn sign(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
    ) -> Result<Self::Signature, Box<dyn Error>>;

    /// Verify a single `signature` matches `message` with `tag` at `index` using `pp` parameter and `pk` public key
    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>>;

    /// Verify aggregate `signature` matches `message_aggregate` with `tag` and `hash_aggregate` using `pp` parameter and `pk` public key
    fn verify_aggregate(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        message_aggregate: &[Self::Message],
        hash_aggregate: &P::G1,
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>>;

    /// Aggregate `signatures` with `weights`
    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight],
    ) -> Result<Self::Signature, Box<dyn Error>>;
}
