use ark_bn254::Bn254;
use ark_ff::{PrimeField, UniformRand};
use ark_std::test_rng;
use blake2::Blake2b512;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use digest::Digest;

use h2s2::{
    holographic_homomorphic_signature_scheme::HolographicHomomorphicSignatureScheme,
    ncs::{Signature, NCS},
}; // Update the path to match your module

type Curve = Bn254;
type Fr = ark_bn254::Fr;
type Hasher = Blake2b512;

const N: usize = 32; // Number of generators

fn benchmark_sign(c: &mut Criterion) {
    let mut rng = test_rng();
    let tag = Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));
    let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");

    let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");
    params.secret_key = Some(sk);
    params.public_key = pk;

    let message = Fr::rand(&mut rng);
    let index = 1;

    // Benchmark group setup with sample size
    let mut group = c.benchmark_group("sign_group");
    group.sample_size(100); // Set the sample size to 100
    group.measurement_time(std::time::Duration::from_secs(10)); // Extend measurement time

    group.bench_with_input(BenchmarkId::new("sign", index), &index, |b, &idx| {
        b.iter(|| {
            let signature = NCS::<Curve, Hasher>::sign(black_box(&params), idx, black_box(message))
                .expect("Sign failed");
            black_box(signature); // Prevent compiler optimizations
        });
    });
    group.finish();
}

fn benchmark_verify(c: &mut Criterion) {
    let mut rng = test_rng();
    let tag = Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));
    let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");

    let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");
    params.secret_key = Some(sk);
    params.public_key = pk;

    let message = Fr::rand(&mut rng);
    let index = 1;
    let signature = NCS::<Curve, Hasher>::sign(&params, index, message).expect("Sign failed");

    // Benchmark group setup with sample size
    let mut group = c.benchmark_group("verify_group");
    group.sample_size(100); // Set the sample size to 100
    group.measurement_time(std::time::Duration::from_secs(10)); // Extend measurement time

    group.bench_with_input(BenchmarkId::new("verify", index), &index, |b, &idx| {
        b.iter(|| {
            let result = NCS::<Curve, Hasher>::verify(
                black_box(&params),
                idx,
                black_box(&message),
                black_box(&signature),
            );
            assert!(result.unwrap());
        });
    });
    group.finish();
}

fn benchmark_verify_aggregate(c: &mut Criterion) {
    let mut rng = test_rng();
    let tag = Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));
    let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");
    let index = 1;

    let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");
    params.secret_key = Some(sk);
    params.public_key = pk;
    let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
    let weights: Vec<usize> = vec![1; N];

    let aggregate_hash =
        NCS::<Curve, Hasher>::precompute(&params, &weights).expect("Precompute failed");

    let signatures: Vec<Signature<Curve>> = messages
        .iter()
        .enumerate()
        .map(|(index, message)| {
            NCS::<Curve, Hasher>::sign(&params, index + 1, *message).expect("Sign failed")
        })
        .collect();

    let aggregated_signature =
        NCS::<Curve, Hasher>::evaluate(&signatures, &weights).expect("Evaluate failed");

    // Benchmark group setup with sample size
    let mut group = c.benchmark_group("verify_aggregate_group");
    group.sample_size(100); // Set the sample size to 100
    group.measurement_time(std::time::Duration::from_secs(10)); // Extend measurement time

    group.bench_with_input(
        BenchmarkId::new("verify_aggregate", 1),
        &index,
        |b, &_idx| {
            b.iter(|| {
                let result = NCS::<Curve, Hasher>::verify_aggregate(
                    black_box(&params),
                    black_box(&aggregate_hash),
                    black_box(&aggregated_signature),
                );
                assert!(result.unwrap());
            });
        },
    );
    group.finish();
}

fn benchmark_evaluate(c: &mut Criterion) {
    let mut rng = test_rng();
    let tag = Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));
    let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");
    let index = 1;

    let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");
    params.secret_key = Some(sk);
    params.public_key = pk;

    let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
    let weights: Vec<usize> = vec![1; N];

    let signatures: Vec<Signature<Curve>> = messages
        .iter()
        .enumerate()
        .map(|(index, message)| {
            NCS::<Curve, Hasher>::sign(&params, index + 1, *message).expect("Sign failed")
        })
        .collect();

    // Benchmark group setup with sample size
    let mut group = c.benchmark_group("evaluate_group");
    group.sample_size(100); // Set the sample size to 100
    group.measurement_time(std::time::Duration::from_secs(10)); // Extend measurement time

    group.bench_with_input(BenchmarkId::new("evaluate", 1), &index, |b, &_idx| {
        b.iter(|| {
            let result =
                NCS::<Curve, Hasher>::evaluate(black_box(&signatures), black_box(&weights));
            assert!(result.is_ok());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_sign,
    benchmark_verify,
    benchmark_verify_aggregate,
    benchmark_evaluate
);
criterion_main!(benches);
