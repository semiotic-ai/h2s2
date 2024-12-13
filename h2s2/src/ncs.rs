use std::ops::{Add, Mul, MulAssign};
use std::{error::Error, marker::PhantomData};

use crate::holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme;
use ark_bn254::{G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
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
    // this public_key is the `u` param in the notes.
    // both the indexer and verifier need it. The secret key
    // remains with the gateway
    pub public_key: P::G2,
    pub secret_key: Option<P::ScalarField>,
    pub max_lanes: usize,
}

#[derive(Clone)]
pub struct Signature<P: Pairing> {
    pub signature: P::G1,
    pub lane_id: usize,
    pub value: P::ScalarField,
}

#[derive(Clone)]
pub struct AggregateSignature<P: Pairing> {
    pub signature: P::G1,
    pub total_value: P::ScalarField,
}

#[derive(Clone)]
pub struct AllocationParameters<P: Pairing> {
    pub allocation_hash: P::G1,
    pub allocation_id: P::ScalarField,
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
    type AggregateSignature = AggregateSignature<P>;

    // n represents the max_lanes amount
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Box<dyn Error>> {
        // Generate the G2 generator
        let g2_generator = P::G2::rand(rng);

        // Prepare the parameters without the secret/public keys
        let g1_generators: Vec<P::G1> = (0..=n).map(|_| P::G1::rand(rng)).collect();
        let mut pp: H2S2Parameters<P> = H2S2Parameters {
            g1_generators,
            g2_generator,
            secret_key: Some(P::ScalarField::zero()), // Temporary placeholder
            public_key: P::G2::zero(),                // Temporary placeholder
            max_lanes: n,
        };

        // Use the keygen function to generate the secret/public key pair
        let (public_key, secret_key) = Self::keygen(&pp, rng)?;

        // Update the parameters with the generated keys
        pp.secret_key = Some(secret_key);
        pp.public_key = public_key;

        Ok(pp)
    }

    //TODO: allocationn_ids (tag in this case) must be unpredictable
    // some random value has to be appended during initialization, prior
    // to the precompute in this function
    fn precompute<R: Rng>(
        _pp: &Self::Parameters,
        rng: &mut R,
        n: usize,
    ) -> Result<(P::G1, P::ScalarField), Box<dyn Error>> {
        let allocation_id = P::ScalarField::rand(rng);
        let hash_vec = (0..n)
            .into_iter()
            .map(|lane_id| {
                let mut message_data = allocation_id.into_bigint().to_bytes_be();
                message_data.append(&mut lane_id.to_be_bytes().to_vec());
                hash_to_g1::<P, D>(message_data)
            })
            .collect::<Vec<_>>();
        let mut allocation_hash = P::G1::zero();
        for hash_val in hash_vec {
            allocation_hash += hash_val;
        }
        Ok((allocation_hash, allocation_id))
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
            lane_id: index,
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
        pk: &Self::PublicKey,
        message_aggregate: &[<P as Pairing>::ScalarField],
        hash_aggregate: &P::G1,
        signature: &Self::AggregateSignature,
    ) -> Result<bool, Box<dyn Error>> {
        let lane_point = hash_aggregate;
        let mut value_point = pp.g1_generators[0].clone();
        value_point.mul_assign(signature.total_value);

        let rhs_pairing = P::pairing(lane_point.add(value_point), pp.public_key);
        let lhs_pairing = P::pairing(signature.signature, pp.g2_generator);
        Ok(lhs_pairing == rhs_pairing)
    }

    fn evaluate(
        signatures: &[Self::Signature],
        _weights: &[Self::Weight],
    ) -> Result<Self::AggregateSignature, Box<dyn Error>> {
        let mut aggregate_signature = P::G1::zero();
        let mut total_value = P::ScalarField::zero();
        for sig in signatures {
            aggregate_signature += sig.signature;
            total_value += sig.value;
        }

        Ok(AggregateSignature {
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
    use blake2::Blake2b512; // Use 512-bit Blake2b for digest
    use once_cell::sync::Lazy;

    static N: usize = 10; // Define the number of generators

    static PARAMS: Lazy<H2S2Parameters<Bn254>> = Lazy::new(|| {
        let mut rng = test_rng();
        NCS::<Bn254, Blake2b512>::setup(&mut rng, N).expect("Setup failed")
    });

    #[test]
    fn test_setup() {
        let params = &*PARAMS;

        assert_eq!(params.g1_generators.len(), 11); // n + 1
        assert_eq!(params.max_lanes, 10);

        let expected_public_key = params.public_key;
        let calculated_public_key = params.g2_generator.mul(params.secret_key.unwrap());

        assert_eq!(
            calculated_public_key, expected_public_key,
            "Public key and private key relation is invalid!"
        );
    }

    #[test]
    fn test_precompute() {
        let params = &*PARAMS;
        let mut rng = test_rng();
        let (hash_aggregate, alloc_id) =
            NCS::<Bn254, Blake2b512>::precompute(&params, &mut rng, N).expect("Precompute failed");

        println!("Precomputed Hash Aggregate: {:?}", hash_aggregate);
        println!("allocation_id {:?}", alloc_id);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let params = &*PARAMS;

        // Precompute the hash aggregate and allocation ID
        let (hash_aggregate, allocation_id) =
            NCS::<Bn254, Blake2b512>::precompute(&params, &mut rng, N).expect("Precompute failed");

        let sk = params.secret_key.unwrap();
        let pk = params.public_key;

        // Generate messages for each lane/index
        let messages: Vec<ark_bn254::Fr> = (0..N).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();

        // Iterate through indices and sign each message
        for index in 0..N {
            // Sign the message with the current index
            let signature =
                NCS::<Bn254, Blake2b512>::sign(&params, allocation_id, index, messages[index])
                    .expect("Sign failed");

            // Verify the signature with the same index
            let is_valid = NCS::<Bn254, Blake2b512>::verify(
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
        let sk = params.secret_key.unwrap();
        let pk = params.public_key;

        // Generate random messages for each lane/index
        let messages: Vec<ark_bn254::Fr> = (0..N).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();

        // Precompute the hash aggregate and allocation ID
        let (hash_aggregate, allocation_id) =
            NCS::<Bn254, Blake2b512>::precompute(&params, &mut rng, N).expect("Precompute failed");

        // Generate individual signatures for each message
        let signatures: Vec<_> = (0..N)
            .map(|index| {
                NCS::<Bn254, Blake2b512>::sign(&params, allocation_id, index, messages[index])
                    .expect("Sign failed")
            })
            .collect();

        // Verify each individual signature
        for (index, signature) in signatures.iter().enumerate() {
            let is_valid = NCS::<Bn254, Blake2b512>::verify(
                &params,
                allocation_id,
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
            NCS::<Bn254, Blake2b512>::evaluate(&signatures, &weights).expect("Evaluate failed");

        // Compute the aggregate message (sum of all messages)
        let message_aggregate: ark_bn254::Fr = messages.iter().copied().sum();

        // Verify the aggregated signature
        let is_valid = NCS::<Bn254, Blake2b512>::verify_aggregate(
            &params,
            &pk,
            &[message_aggregate],
            &hash_aggregate,
            &aggregated_signature,
        )
        .expect("Verify failed");

        assert!(
            is_valid,
            "Aggregated signature verification failed for the entire set of messages!"
        );

        println!(
            "Aggregated signature successfully verified for all {} messages!",
            N
        );
    }
}
