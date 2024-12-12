use std::{error::Error, marker::PhantomData, ops::MulAssign};

use crate::holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme;
use ark_bn254::{G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, UniformRand, Zero};
use ark_std::rand::Rng;
use digest::Digest;

pub struct NC1<P: Pairing, D: Digest> {
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}

pub struct H2S2Parameters {
    pub g1_generators: Vec<G1Projective>,
    pub g2_generator: G2Projective,
    pub public_key: G2Projective,
    pub max_lanes: usize,
}

impl<P: Pairing, D: Digest + Send + Sync> HolographicHomomorphicSignatureScheme<P, D>
    for NC1<P, D>
{
    type Parameters = H2S2Parameters;
    type PublicKey = P::G2;
    type SecretKey = P::ScalarField;
    type Signature = P::G1;
    type Message = P::ScalarField;
    type Weight = usize;

    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Box<dyn Error>> {
        let g2_generator = G2Projective::rand(rng);

        // Note that although max_lanes number of generators are specificied, we only use the first one in practice
        // TODO: In here, we use only the first Generator. But why are there n+1 generators? Not just n? In the paper
        // it is mentioned that we need n. And why just use the first one if we n?
        Ok(H2S2Parameters {
            g1_generators: (0..=n).map(|_| G1Projective::rand(rng)).collect(),
            g2_generator,
            public_key: g2_generator.clone(),
            max_lanes: n, // Set max_lanes to the number of generators
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_std::test_rng;
    use blake2::Blake2b512; // Use 512-bit Blake2b for digest

    #[test]
    fn test_setup() {
        let mut rng = test_rng();
        let n = 10; // Define the number of generators
                    //TODO: figure what OutSize of Blake2b we should use. Is 512 OK?
        let params = NC1::<Bn254, Blake2b512>::setup(&mut rng, n).expect("Setup failed");

        assert_eq!(params.g1_generators.len(), n + 1);
        assert_eq!(params.max_lanes, n);
    }
}
