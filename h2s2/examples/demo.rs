// Copyright 2025-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::Bn254;
use ark_ff::{PrimeField, UniformRand};
use ark_std::test_rng;
use blake2::Blake2b512;
use digest::Digest;
use h2s2::holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme;
use h2s2::ncs::NCS;

fn main() {
    type Curve = Bn254;
    type Fr = ark_bn254::Fr;
    type Hasher = Blake2b512;
    const N: usize = 32; // Define the number of generators

    let mut rng = test_rng();

    // Setup parameters
    let tag = Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));
    let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");

    // Generate key pair
    let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");
    params.secret_key = Some(sk);
    params.public_key = pk;

    // Generate messages
    let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();

    // Sign messages
    let signatures: Vec<_> = (1..=N)
        .map(|index| {
            NCS::<Curve, Hasher>::sign(&params, index, messages[index - 1]).expect("Sign failed")
        })
        .collect();

    // Verify signatures
    for (index, signature) in signatures.iter().enumerate() {
        let is_valid =
            NCS::<Curve, Hasher>::verify(&params, index + 1, &messages[index], signature)
                .expect("Verify failed");

        assert!(
            is_valid,
            "Signature verification failed for index {}",
            index + 1
        );
    }

    // Precompute hash aggregate
    let weights: Vec<usize> = vec![1; N];
    let aggregate_hash =
        NCS::<Curve, Hasher>::precompute(&params, &weights).expect("Precompute failed");

    // Aggregate signatures
    let aggregated_signature =
        NCS::<Curve, Hasher>::evaluate(&signatures, &weights).expect("Evaluate failed");

    // Verify aggregated signature
    let is_valid =
        NCS::<Curve, Hasher>::verify_aggregate(&params, &aggregate_hash, &aggregated_signature)
            .expect("Verify failed");

    assert!(is_valid, "Aggregated signature verification failed!");

    println!("All signatures verified successfully!");
}
