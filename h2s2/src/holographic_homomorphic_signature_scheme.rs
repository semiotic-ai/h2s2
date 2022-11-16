//nc1
use crate::ark_std::UniformRand;
use crate::ark_std::Zero;
use crate::Error;
use crate::HomomorphicSignatureScheme;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_std::{marker::PhantomData, rand::Rng};
use digest::Digest;
use std::ops::MulAssign;

pub struct HolographicHomomorphicSignatureScheme<P: Pairing, D: Digest> {
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}

#[derive(Clone)]
pub struct H2S2Parameters<P: Pairing> {
    pub g1_generators: Vec<P::G1>,
    pub g2_generator: P::G2,
}

impl<P: Pairing, D: Digest + Send + Sync> HolographicHomomorphicSignatureScheme for NC1<P, D> {
    type Parameters = H2S2Parameters<P>;
    type PublicKey = P::G2;
    type SecretKey = P::ScalarField;
    type Signature = P::G1;
    type Message = P::ScalarField;
    type Weight = usize;

    /// Generate G2 element and `n` G1 elements
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Error> {}

    /// Generate hash aggregate (H_a) with `tag` and `n` lanes
    fn precompute(tag: &[u8], n: usize) -> Result<P::G1, Error> {}

    /// Generate private and public receipt keys using `pp` parameters from `setup`
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
    }

    /// Sign `message` with `tag` at `index`
    fn sign(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
    ) -> Result<Self::Signature, Error> {
    }

    /// Verify a single `signature` matches `message` with `tag` at `index` using `pp` parameter and `pk` public key
    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
    }

    /// Verify aggregate `signature` matches `message_aggregate` with `tag` and `hash_aggregate`using `pp` parameter and `pk` public key
    fn verify_aggregate(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        message_aggregate: &[Self::Message],
        hash_aggregate: &P::G1,
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
    }

    /// Aggregate `signatures` with `weights`
    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight],
    ) -> Result<Self::Signature, Error> {
    }
}
