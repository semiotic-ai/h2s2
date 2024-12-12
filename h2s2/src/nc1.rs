use std::ops::Mul;
use std::{error::Error, marker::PhantomData};

use crate::holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme;
use ark_bn254::{G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_ff::{BigInteger, UniformRand, Zero};
use ark_std::rand::Rng;
use digest::Digest;

pub struct NC1<P: Pairing, D: Digest> {
    parameters: Option<H2S2Parameters<P>>,
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}

pub struct H2S2Parameters<P: Pairing> {
    pub g1_generators: Vec<P::G1>,
    pub g2_generator: P::G2,
    // this public_key is the `u` param in the notes.
    // both the indexer and verifier need it. The secret key
    // remains with the gateway
    pub public_key: P::G2,
    pub secret_key: P::ScalarField,
    pub max_lanes: usize,
}

impl<P: Pairing, D: Digest + Send + Sync> HolographicHomomorphicSignatureScheme<P, D>
    for NC1<P, D>
{
    type Parameters = H2S2Parameters<P>;
    type PublicKey = P::G2;
    type SecretKey = P::ScalarField;
    type Signature = P::G1;
    type Message = P::ScalarField;
    type Weight = usize;

    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Box<dyn Error>> {
        // Generate the G2 generator
        let g2_generator = P::G2::rand(rng);

        // Prepare the parameters without the secret/public keys
        let g1_generators: Vec<P::G1> = (0..=n).map(|_| P::G1::rand(rng)).collect();
        let mut pp = H2S2Parameters {
            g1_generators,
            g2_generator,
            secret_key: P::ScalarField::zero(), // Temporary placeholder
            public_key: P::G2::zero(),          // Temporary placeholder
            max_lanes: n,
        };

        // Use the keygen function to generate the secret/public key pair
        let (public_key, secret_key) = Self::keygen(&pp, rng)?;

        // Update the parameters with the generated keys
        pp.secret_key = secret_key;
        pp.public_key = public_key;

        Ok(pp)
    }

    //TODO: allocationn_ids (tag in this case) must be unpredictable
    // some random value has to be appended during initialization, prior
    // to the precompute in this function
    fn precompute(pp: &Self::Parameters, tag: &[u8], n: usize) -> Result<P::G1, Box<dyn Error>> {
        use ark_std::vec::Vec;

        // Initialize the hash aggregate
        let mut hash_aggregate = P::G1::zero();

        // Iterate through the lane IDs from 1 to N
        for lane_id in 1..=n {
            //TODO: in the original, the allocation_id is a random value from
            // the ScalarField. What is different here from using the u8 slice?
            // let allocation_id = P::Fr::rand(rng);

            // Concatenate the tag (allocationId) with the lane ID
            let mut input = Vec::from(tag);
            input.extend_from_slice(&lane_id.to_le_bytes());

            // Hash the concatenated input to generate a scalar value
            let hash_scalar = P::ScalarField::from_le_bytes_mod_order(D::digest(&input).as_ref());

            // Map the scalar to a G1 element
            let hash_point = pp.g1_generators[0].mul(hash_scalar);

            // Add the resulting point to the hash aggregate
            hash_aggregate += hash_point;
        }

        Ok(hash_aggregate)
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Box<dyn Error>> {
        // Generate the private key as a random scalar
        let secret_key = P::ScalarField::rand(rng);

        // Compute the public key as the secret_key multiplied by the G2 generator
        let public_key = pp.g2_generator.mul(secret_key);

        Ok((public_key, secret_key))
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
    use once_cell::sync::Lazy;

    static N: usize = 10; // Define the number of generators

    static PARAMS: Lazy<H2S2Parameters<Bn254>> = Lazy::new(|| {
        let mut rng = test_rng();
        NC1::<Bn254, Blake2b512>::setup(&mut rng, N).expect("Setup failed")
    });

    #[test]
    fn test_setup() {
        let params = &*PARAMS;

        assert_eq!(params.g1_generators.len(), 11); // n + 1
        assert_eq!(params.max_lanes, 10);

        let expected_public_key = params.public_key;
        let calculated_public_key = params.g2_generator.mul(params.secret_key);

        assert_eq!(
            calculated_public_key, expected_public_key,
            "Public key and private key relation is invalid!"
        );
    }

    #[test]
    fn test_precompute() {
        let params = &*PARAMS;
        let allocation_id = b"example_allocation_id";

        let hash_aggregate = NC1::<Bn254, Blake2b512>::precompute(&params, allocation_id, N)
            .expect("Precompute failed");

        println!("Precomputed Hash Aggregate: {:?}", hash_aggregate);
    }
}
