// Copyright 2025-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use digest::Digest;
use std::error::Error;

pub trait HolographicHomomorphicSignatureScheme<P: Pairing, D: Digest + Send + Sync> {
    type Parameters;
    type PublicKey;
    type SecretKey;
    type Signature;
    type Message;
    type Weight;
    type AggregatedSignature;

    /// Generate one G2 element and `n` G1 elements
    fn setup(n: usize, tag: P::ScalarField) -> Result<Self::Parameters, Box<dyn Error>>;

    /// Precompute `aggregate_hash` using H2S2 instance parameters
    fn precompute(pp: &Self::Parameters, weights: &[Self::Weight])
        -> Result<P::G1, Box<dyn Error>>;

    /// Generate private and public receipt keys using `pp` parameters from `setup`
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Box<dyn Error>>;

    /// Sign `message` with `tag` at `index`
    fn sign(
        pp: &Self::Parameters,
        index: usize,
        message: Self::Message,
    ) -> Result<Self::Signature, Box<dyn Error>>;

    /// Verify a single `signature` matches `message` with `tag` at `index` using `pp` parameter and `pk` public key
    fn verify(
        pp: &Self::Parameters,
        index: usize,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>>;

    /// Verify an aggregate `signature` using a pre-computed `hash_aggregate` with `tag` using `pp`
    /// parameter and `pk` public key
    fn verify_aggregate(
        pp: &Self::Parameters,
        hash_aggregate: &P::G1,
        signature: &Self::AggregatedSignature,
    ) -> Result<bool, Box<dyn Error>>;

    /// Calculate an aggregate signature using `signatures` and `weights`
    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight],
    ) -> Result<Self::AggregatedSignature, Box<dyn Error>>;
}
