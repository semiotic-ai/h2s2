// Copyright 2025-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, Mul, MulAssign};
use std::{error::Error, marker::PhantomData};

use crate::holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_ff::{BigInteger, UniformRand, Zero};
use ark_std::rand::Rng;
use digest::Digest;

fn hash_to_g1<P: Pairing, D: Digest>(message_data: Vec<u8>) -> P::G1Affine {
    let mut g1_point: Option<P::G1Affine> = None;
    let mut counter = 0;
    while g1_point.is_none() {
        let mut tmp_message = message_data.clone();
        tmp_message.push(counter);
        let hash_out = D::digest(&tmp_message);
        g1_point = P::G1Affine::from_random_bytes(&hash_out);
        counter += 1;
    }
    g1_point.unwrap()
}

/// H2S2 instantiated with [NCS1](https://eprint.iacr.org/2008/316.pdf) scheme.
pub struct NCS<P: Pairing, D: Digest> {
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}

/// Parameters for the H2S2 scheme.
/// This implementation is based on the [NCS1](https://eprint.iacr.org/2008/316.pdf) scheme.
/// We additionally include a `max_size` parameter to enable precomputation for efficient on-chain
/// verification.
pub struct H2S2Parameters<P: Pairing> {
    pub tag: P::ScalarField,
    pub g1_generators: Vec<P::G1>,
    pub g2_generator: P::G2,
    pub public_key: P::G2,
    pub secret_key: Option<P::ScalarField>,
    pub max_size: usize,
}

/// A signature for a single `index` and `value` pair.
#[derive(Clone)]
pub struct Signature<P: Pairing> {
    pub signature: P::G1,
    pub index: usize,
    pub value: P::ScalarField,
}

/// A aggregated signature using `max_size` unique `index`s.
#[derive(Clone)]
pub struct AggregatedSignature<P: Pairing> {
    pub signature: P::G1,
    pub total_value: P::ScalarField,
}

impl<P: Pairing, D: Digest + Send + Sync> HolographicHomomorphicSignatureScheme<P, D>
    for NCS<P, D>
{
    type Parameters = H2S2Parameters<P>;
    type PublicKey = P::G2;
    type SecretKey = P::ScalarField;
    type Signature = Signature<P>;
    type Message = P::ScalarField;
    type Weight = usize;
    type AggregatedSignature = AggregatedSignature<P>;

    // n represents the max_lanes amount
    fn setup(n: usize, tag: P::ScalarField) -> Result<Self::Parameters, Box<dyn Error>> {
        // Use the hardcoded G2 generator from the Pairing trait
        let g2_generator = P::G2::generator();

        // Generate a deterministic set of G1 generators based on the hardcoded G1 generator
        let mut g1_generators = vec![P::G1::generator()];
        for index in 0..n {
            let mut message_data = tag.into_bigint().to_bytes_be();
            message_data.append(&mut index.to_be_bytes().to_vec());
            g1_generators.push(hash_to_g1::<P, D>(message_data).into())
        }

        // Initialize parameters without secret/public keys
        let pp: H2S2Parameters<P> = H2S2Parameters {
            tag,
            g1_generators,
            g2_generator,
            secret_key: Some(P::ScalarField::zero()),
            public_key: P::G2::zero(),
            max_size: n,
        };

        Ok(pp)
    }

    fn precompute(
        pp: &Self::Parameters,
        weights: &[Self::Weight],
    ) -> Result<P::G1, Box<dyn Error>> {
        let lane_points = &pp.g1_generators[1..];
        let aggregate_hash = lane_points
            .iter()
            .zip(weights.iter())
            .fold(P::G1::zero(), |acc, (point, &weight)| {
                acc + point.mul(P::ScalarField::from(weight as u64))
            });
        Ok(aggregate_hash)
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
        index: usize,
        message: <P as Pairing>::ScalarField,
    ) -> Result<Self::Signature, Box<dyn Error>> {
        let index_point = pp.g1_generators[index];

        let mut value_point = pp.g1_generators[0];
        value_point.mul_assign(message);

        let message_point = index_point + value_point;
        let mut signature = message_point;
        signature.mul_assign(pp.secret_key.unwrap());
        Ok(Signature {
            signature,
            index,
            value: message,
        })
    }

    fn verify(
        pp: &Self::Parameters,
        index: usize,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>> {
        if (1..=pp.max_size).contains(&index) {
            let lane_point = pp.g1_generators[index];

            let mut value_point = pp.g1_generators[0];
            value_point.mul_assign(message);

            let rhs_pairing = P::pairing(lane_point + value_point, pp.public_key);
            let lhs_pairing = P::pairing(signature.signature, pp.g2_generator);
            Ok(lhs_pairing == rhs_pairing)
        } else {
            Err(format!("Value {} is out of range [{}, {}]", index, 1, pp.max_size).into())
        }
    }

    fn verify_aggregate(
        pp: &Self::Parameters,
        aggregate_hash: &P::G1,
        signature: &Self::AggregatedSignature,
    ) -> Result<bool, Box<dyn Error>> {
        let lane_point = aggregate_hash;
        let mut value_point = pp.g1_generators[0];
        value_point.mul_assign(signature.total_value);

        let rhs_pairing = P::pairing(lane_point.add(value_point), pp.public_key);
        let lhs_pairing = P::pairing(signature.signature, pp.g2_generator);
        Ok(lhs_pairing == rhs_pairing)
    }

    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight],
    ) -> Result<Self::AggregatedSignature, Box<dyn Error>> {
        // Ensure that the lengths of the inputs match
        if signatures.len() != weights.len() {
            return Err("Signatures and weights must have the same length".into());
        }

        let mut aggregate_signature = P::G1::zero();
        let mut total_value = P::ScalarField::zero();

        for (sig, &wt) in signatures.iter().zip(weights.iter()) {
            let weight_scalar = P::ScalarField::from(wt as u64);
            aggregate_signature += sig.signature.mul(weight_scalar);
            total_value += weight_scalar.mul(sig.value);
        }

        Ok(AggregatedSignature {
            signature: aggregate_signature,
            total_value,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_bn254::Bn254;
    use ark_std::test_rng;
    use once_cell::sync::Lazy;
    type Curve = Bn254;
    type Fr = ark_bn254::Fr;
    type Hasher = blake2::Blake2b512;
    static N: usize = 32; // Define the number of generators

    static PARAMS: Lazy<H2S2Parameters<Curve>> = Lazy::new(|| {
        let mut rng = test_rng();

        let tag = ark_bn254::Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));
        let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");

        // Generate the secret and public keys using keygen
        let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");

        params.secret_key = Some(sk);
        params.public_key = pk;
        params
    });

    #[test]
    fn test_setup_and_keygen() {
        // Use the correct WBConfig implementation for G1

        let mut rng = test_rng();
        let n = N;

        let params = &*PARAMS; // Explicit reference to PARAMS

        let (pk, sk) = NCS::<Curve, Hasher>::keygen(params, &mut rng).expect("Keygen failed");

        assert_eq!(
            params.g1_generators.len(),
            n + 1,
            "Incorrect number of G1 generators"
        );
        assert_eq!(params.max_size, n, "Max lanes value 'mismatch");

        // Verify the public key matches the secret key and G2 generator relationship
        let calculated_public_key = params.g2_generator.mul(sk);
        assert_eq!(
            calculated_public_key, pk,
            "Public key does not match the calculated value from secret key and G2 generator"
        );

        println!("Setup and Keygen tests passed!");
    }

    #[test]
    fn test_precompute() {
        let params = &*PARAMS;

        // Generate weights (all set to 1 for uniform aggregation)
        let weights: Vec<usize> = vec![1; N];

        let aggregate_hash =
            NCS::<Curve, Hasher>::precompute(params, &weights).expect("Precompute failed");

        println!("Precomputed Hash Aggregate: {:?}", aggregate_hash);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let params = &*PARAMS;

        // Generate messages for each lane/index
        let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();

        // Iterate through indices and sign each message
        messages.iter().enumerate().for_each(|(index, message)| {
            // Sign the message with the current index
            let signature =
                NCS::<Curve, Hasher>::sign(params, index + 1, *message).expect("Sign failed");

            // Verify the signature with the same index
            let is_valid =
                NCS::<Curve, Hasher>::verify(params, index + 1, &messages[index], &signature)
                    .expect("Verify failed");

            assert!(
                is_valid,
                "Signature verification failed for index {}!",
                index
            );
        });

        println!("All signatures successfully verified for indices 0..{}!", N);
    }

    #[test]
    fn test_aggregate() {
        let mut rng = test_rng();
        let params = &*PARAMS;

        // Generate random messages for each lane/index
        let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();

        // Generate weights (all set to 1 for uniform aggregation)
        let weights: Vec<usize> = vec![1; N];

        // Precompute the hash aggregate and tag
        let aggregate_hash =
            NCS::<Curve, Hasher>::precompute(params, &weights).expect("Precompute failed");

        // Generate individual signatures for each message
        let mut signatures: Vec<_> = (0..N)
            .map(|index| {
                NCS::<Curve, Hasher>::sign(params, index + 1, messages[index]).expect("Sign failed")
            })
            .collect();

        // Verify each individual signature
        for (index, signature) in signatures.iter().enumerate() {
            let is_valid =
                NCS::<Curve, Hasher>::verify(params, index + 1, &messages[index], signature)
                    .expect("Verify failed");
            assert!(is_valid, "Invalid signature for index {}!", index);
        }

        // Aggregate the signatures
        let aggregated_signature =
            NCS::<Curve, Hasher>::evaluate(&signatures, &weights).expect("Evaluate failed");

        // Verify the aggregated signature
        let is_valid =
            NCS::<Curve, Hasher>::verify_aggregate(params, &aggregate_hash, &aggregated_signature)
                .expect("Verify failed");

        assert!(
            is_valid,
            "Aggregated signature verification failed for the entire set of messages!"
        );

        println!(
            "Aggregated signature successfully verified for all {} messages!",
            N
        );

        // this next signature aggregation test should fail
        // Introduce a duplicate signature to simulate a lying indexer
        let random_index = rng.gen_range(0..N);
        let duplicate_signature = signatures[random_index].clone();
        signatures.push(duplicate_signature);
        // adds 1 more weight to match the added signature
        let weights: Vec<usize> = vec![1; N + 1];

        // Aggregate the signatures, including the duplicate
        let tampered_aggregate_signature =
            NCS::<Curve, Hasher>::evaluate(&signatures, &weights).expect("Evaluate failed");

        // Verify the aggregated signature with the tampered signature table
        let is_valid = NCS::<Curve, Hasher>::verify_aggregate(
            params,
            &aggregate_hash,
            &tampered_aggregate_signature,
        )
        .expect("Verify failed");

        // Assert that verification fails
        assert!(
            !is_valid,
            "Aggregated signature verification should fail with a tampered signature table!"
        );

        println!("Tampered aggregated signature verification correctly failed as expected!");
    }
}
