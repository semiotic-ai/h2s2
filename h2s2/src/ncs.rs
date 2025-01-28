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
    while g1_point.is_some() == false {
        let mut tmp_message = message_data.clone();
        tmp_message.push(counter);
        let hash_out = D::digest(&tmp_message);
        g1_point = P::G1Affine::from_random_bytes(&hash_out);
        counter += 1;
    }
    g1_point.unwrap()
}

pub struct NCS<P: Pairing, D: Digest> {
    _pairing: PhantomData<P>,
    _hash: PhantomData<D>,
}

pub struct H2S2Parameters<P: Pairing> {
    pub g1_generators: Vec<P::G1>,
    pub g2_generator: P::G2,
    pub public_key: P::G2,
    pub secret_key: Option<P::ScalarField>,
    pub max_lanes: usize,
}

#[derive(Clone)]
pub struct Signature<P: Pairing> {
    pub signature: P::G1,
    pub index: usize,
    pub value: P::ScalarField,
}

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
    fn setup(n: usize) -> Result<Self::Parameters, Box<dyn Error>> {
        // Use the hardcoded G2 generator from the Pairing trait
        let g2_generator = P::G2::generator();

        // Generate a deterministic set of G1 generators based on the hardcoded G1 generator
        let g1_base_generator = P::G1::generator();
        // In practice, we only ever use the first g1 generator
        // so it is going to be generated only g1[0]
        let g1_generators = vec![g1_base_generator];

        // Initialize parameters without secret/public keys
        let pp: H2S2Parameters<P> = H2S2Parameters {
            g1_generators,
            g2_generator,
            secret_key: Some(P::ScalarField::zero()), 
            public_key: P::G2::zero(),                
            max_lanes: n,
        };

        Ok(pp)
    }

    fn precompute(
        _pp: &Self::Parameters,
        tag: P::ScalarField,
        n: usize,
    ) -> Result<(P::G1, P::ScalarField), Box<dyn Error>> {
        let hash_vec = (0..n)
            .into_iter()
            .map(|index| {
                let mut message_data = tag.into_bigint().to_bytes_be();
                message_data.append(&mut index.to_be_bytes().to_vec());
                hash_to_g1::<P, D>(message_data)
            })
            .collect::<Vec<_>>();
        let mut allocation_hash = P::G1::zero();
        for hash_val in hash_vec {
            allocation_hash += hash_val;
        }
        Ok((allocation_hash, tag))
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
        tag: P::ScalarField,
        index: usize,
        message: <P as Pairing>::ScalarField,
    ) -> Result<Self::Signature, Box<dyn Error>> {
        let mut lane_data = tag.into_bigint().to_bytes_be();
        lane_data.append(&mut index.to_be_bytes().to_vec());
        let lane_point = hash_to_g1::<P, D>(lane_data);

        let mut value_point = pp.g1_generators[0].clone();
        value_point.mul_assign(message);

        let message_point = lane_point.into_group() + value_point;
        let mut signature = message_point.clone();
        signature.mul_assign(pp.secret_key.unwrap());
        Ok(Signature {
            signature,
            index,
            value: message,
        })
    }

    fn verify(
        pp: &Self::Parameters,
        tag: P::ScalarField,
        index: usize,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>> {
        let mut lane_data = tag.into_bigint().to_bytes_be();
        lane_data.append(&mut index.to_be_bytes().to_vec());
        let lane_point = hash_to_g1::<P, D>(lane_data);

        let mut value_point = pp.g1_generators[0].clone();
        value_point.mul_assign(message);

        let rhs_pairing = P::pairing(lane_point.into_group() + value_point, pp.public_key);
        let lhs_pairing = P::pairing(signature.signature, pp.g2_generator);
        Ok(lhs_pairing == rhs_pairing)
    }

    fn verify_aggregate(
        pp: &Self::Parameters,
        aggregate_hash: &P::G1,
        signature: &Self::AggregatedSignature,
    ) -> Result<bool, Box<dyn Error>> {
        let lane_point = aggregate_hash;
        let mut value_point = pp.g1_generators[0].clone();
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
    //we could also use the ark_bls12_381 curve which was intended to substitute this one:
    //https://docs.rs/ark-bls12-381/latest/ark_bls12_381/
    // Ethereum is reviewing using it:
    // https://eips.ethereum.org/EIPS/eip-2537
    // use ark_bls12_381::Bn254;
    use ark_std::test_rng;
    use once_cell::sync::Lazy;
    type Curve = Bn254;
    type Fr = ark_bn254::Fr;
    type Hasher = blake2::Blake2b512;
    static N: usize = 10; // Define the number of generators

    static PARAMS: Lazy<H2S2Parameters<Curve>> = Lazy::new(|| {
        let mut rng = test_rng();

        let mut params = NCS::<Curve, Hasher>::setup(N).expect("Setup failed");

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
        let n = 10;

        let params = &*PARAMS; // Explicit reference to PARAMS

        let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");

        assert_eq!(
            params.g1_generators.len(),
            1,
            "Incorrect number of G1 generators"
        );
        assert_eq!(params.max_lanes, n, "Max lanes value 'mismatch");

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

        let tag = ark_bn254::Fr::from_be_bytes_mod_order(&Hasher::digest(&b"test"));
        let (hash_aggregate, tag) =
            NCS::<Curve, Hasher>::precompute(&params, tag, N).expect("Precompute failed");

        println!("Precomputed Hash Aggregate: {:?}", hash_aggregate);
        println!("allocation_id {:?}", tag);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let params = &*PARAMS;

        // Precompute the hash aggregate and allocation ID
        let tag = ark_bn254::Fr::from_be_bytes_mod_order(&Hasher::digest(&b"test"));
        let (_, allocation_id) =
            NCS::<Curve, Hasher>::precompute(&params, tag, N).expect("Precompute failed");

        // Generate messages for each lane/index
        let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();

        // Iterate through indices and sign each message
        for index in 0..N {
            // Sign the message with the current index
            let signature =
                NCS::<Curve, Hasher>::sign(&params, allocation_id, index, messages[index])
                    .expect("Sign failed");

            // Verify the signature with the same index
            let is_valid = NCS::<Curve, Hasher>::verify(
                &params,
                allocation_id,
                index,
                &messages[index],
                &signature,
            )
            .expect("Verify failed");

            assert!(
                is_valid,
                "Signature verification failed for index {}!",
                index
            );
        }

        println!("All signatures successfully verified for indices 0..{}!", N);
    }

    #[test]
    fn test_aggregate() {
        let mut rng = test_rng();
        let params = &*PARAMS;

        // Generate random messages for each lane/index
        let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();

        // Precompute the hash aggregate and tag 
        let tag = ark_bn254::Fr::from_be_bytes_mod_order(&Hasher::digest(&b"test"));
        let (hash_aggregate, tag) =
            NCS::<Curve, Hasher>::precompute(&params, tag, N).expect("Precompute failed");

        // Generate individual signatures for each message
        let mut signatures: Vec<_> = (0..N)
            .map(|index| {
                NCS::<Curve, Hasher>::sign(&params, tag, index, messages[index])
                    .expect("Sign failed")
            })
            .collect();

        // Verify each individual signature
        for (index, signature) in signatures.iter().enumerate() {
            let is_valid = NCS::<Curve, Hasher>::verify(
                &params,
                tag,
                index,
                &messages[index],
                signature,
            )
            .expect("Verify failed");
            assert!(is_valid, "Invalid signature for index {}!", index);
        }

        // Generate weights (all set to 1 for uniform aggregation)
        let weights: Vec<usize> = vec![1; N];

        // Aggregate the signatures
        let aggregated_signature =
            NCS::<Curve, Hasher>::evaluate(&signatures, &weights).expect("Evaluate failed");

        // Verify the aggregated signature
        let is_valid =
            NCS::<Curve, Hasher>::verify_aggregate(&params, &hash_aggregate, &aggregated_signature)
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
            &params,
            &hash_aggregate,
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
