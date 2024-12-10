
use ark_std::UniformRand;
use ark_std::Zero;
use std::error::Error;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_std::{marker::PhantomData, rand::Rng};
use digest::Digest;
use std::ops::MulAssign;

use crate::holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme;

pub struct NC1<P: Pairing, D: Digest> {
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}


#[derive(Clone)]
pub struct H2S2Parameters<P: Pairing> {
    pub g1_generators: Vec<P::G1>,
    pub g2_generator: P::G2,
}

impl<P: Pairing, D: Digest + Send + Sync> HolographicHomomorphicSignatureScheme<P, D> for NC1<P, D> {
    type Parameters = H2S2Parameters<P>;
    type PublicKey = P::G2;
    type SecretKey = P::ScalarField;
    type Signature = P::G1;
    type Message = P::ScalarField;
    type Weight = usize;

    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Box<dyn Error>> {
        Ok(H2S2Parameters {
            g1_generators: vec![P::G1::rand(rng); n],
            g2_generator: P::G2::rand(rng),
        })
    }

    fn precompute(tag: &[u8], n: usize) -> Result<P::G1, Box<dyn Error>> {
        Ok(P::G1::default())
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Box<dyn Error>> {
        Ok((P::G2::rand(rng), P::ScalarField::rand(rng)))
    }

    fn sign(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
    ) -> Result<Self::Signature, Box<dyn Error>> {
        Ok(P::G1::default())
    }

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        index: &[u8],
        message: &[Self::Message],
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>> {
        Ok(true)
    }

    fn verify_aggregate(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        tag: &[u8],
        message_aggregate: &[Self::Message],
        hash_aggregate: &P::G1,
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>> {
        Ok(true)
    }

    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight],
    ) -> Result<Self::Signature, Box<dyn Error>> {
        Ok(P::G1::default())
    }
}
