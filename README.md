# Holographic Homomorphic Signature Scheme (H2S2)

The **Holographic Homomorphic Signature Scheme (H2S2)** library is a cryptographic implementation of a holographic homomorphic signature scheme based on the [NCS1](https://eprint.iacr.org/2008/316.pdf) protocol. 

Homomorphic signatures allow for the aggregation of multiple signatures into a single signature. This aggregate signature is a valid signature for the weighted sum of the original messages.

A hologrophic homomorphic signature scheme uses a precomputation step to make the aggregate verification process more efficient. See this white paper for more detail.

This library is implemented using the `ark-works` cryptographic ecosystem and provides an extensible trait for other signature schemes that follow a similar design.

---

## How It Works
It is helpful to think of homomorphic signatures as signing a table of data. A signer will sign messages corresponding to the rows of a table, each table must have a unique `tag` to distinguish signatures from other tables. Each row can is assigned a unique index and the message for that row can be signed independently. A signer can sign and send many messages but each one must have a unique index (i.e. row id). A receiver in possesion of many row signatures for a given table can aggregate them into a single signature. This aggregated signature can be verified by a by anyone using the public key of the signer.

At high-level there are 6 main functions in an H2S2. 

### 1. **Setup**
This initializes the public parameters for an instance of the protocol

### 2. **Key Generation**
Calculate the private signing key and the public verification key.

### 3. **Signing Messages**
`sign` creates a signature for a message and an index. The signature is computed using the cryptographic parameters and the private key.

### 4. **Verifying Signatures**
`verify` ensures that a given signature matches the provided message, index, and public key.

### 5. **Aggregating Signatures**
`evaluate` combines multiple signatures into a single aggregated signature. It ensures weighted contributions based on the provided weights.

### 6. **Verifying Aggregated Signatures**
`verify_aggregate` validates the aggregated signature using precomputed hash aggregates and cryptographic parameters.

---

## Example Usage
```rust
    use ark_bn254::Bn254;
    use ark_std::test_rng;
    use once_cell::sync::Lazy;
    type Curve = Bn254;
    type Fr = ark_bn254::Fr;
    type Hasher = blake2::Blake2b512;
    
    // Setup a new instance using up to 32 rows
    static N: usize = 32; 

    let mut rng = test_rng();

    // Generate a unique tag for the table instance
    let tag = ark_bn254::Fr::from_be_bytes_mod_order(&Hasher::digest(b"test"));

    // Configure the parameters for the scheme. 
    // Calculates row keys and value keys.
    let mut params = NCS::<Curve, Hasher>::setup(N, tag).expect("Setup failed");

    // Generate the secret and public keys using keygen
    let (pk, sk) = NCS::<Curve, Hasher>::keygen(&params, &mut rng).expect("Keygen failed");
    params.secret_key = Some(sk);
    params.public_key = pk;


    // Generate random messages for each lane/index
    let messages: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();

    // Generate weights (all set to 1 for uniform aggregation)
    let weights: Vec<usize> = vec![1; N];

    // Precompute the hash aggregate and tag
    let aggregate_hash = NCS::<Curve, Hasher>::precompute(params).expect("Precompute failed");

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
    ```
