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
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::Parameters, Box<dyn Error>>;

    /// Generate hash aggregate (H_a) with `tag` and `n` lanes, and a
    /// allocation_id as a ScalarField
    fn precompute<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
        n: usize,
    ) -> Result<(P::G1, P::ScalarField), Box<dyn Error>>;

    /// Generate private and public receipt keys using `pp` parameters from `setup`
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Box<dyn Error>>;

    /// Sign `message` with `tag` at `index`
    fn sign(
        pp: &Self::Parameters,
        tag: P::ScalarField,
        index: usize,
        message: Self::Message,
    ) -> Result<Self::Signature, Box<dyn Error>>;

    /// Verify a single `signature` matches `message` with `tag` at `index` using `pp` parameter and `pk` public key
    ///  TODO: index should be restricted to a number from 1 to N (max number of lanes)
    fn verify(
        pp: &Self::Parameters,
        tag: P::ScalarField,
        index: usize,
        message: &Self::Message,
        signature: &Self::Signature,
    ) -> Result<bool, Box<dyn Error>>;

    /// Verify aggregate `signature` matches `message_aggregate`
    /// contained in [`AggregatedSignature`] with `tag` and `hash_aggregate` using `pp` parameter and `pk` public key
    fn verify_aggregate(
        pp: &Self::Parameters,
        // tag: &[u8],
        hash_aggregate: &P::G1,
        signature: &Self::AggregatedSignature,
    ) -> Result<bool, Box<dyn Error>>;

    /// Aggregate `signatures` with `weights`
    fn evaluate(
        signatures: &[Self::Signature],
        weights: &[Self::Weight],
    ) -> Result<Self::AggregatedSignature, Box<dyn Error>>;
}
