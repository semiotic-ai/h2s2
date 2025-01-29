# Holographic Homomorphic Signature Scheme (H2S2)

The **Holographic Homomorphic Signature Scheme (H2S2)** library is a cryptographic implementation of a holographic homomorphic signature scheme based on the [NCS1](https://eprint.iacr.org/2008/316.pdf) protocol. 

Homomorphic signatures allow for the aggregation of multiple signatures into a single signature. This aggregate signature is a valid signature for the weighted sum of the original messages.

A hologrophic homomorphic signature scheme uses a precomputation step to make the aggregate verification process more efficient. See this white paper for more detail.

A note on the name `Holographic`. We were inspired by [Marlin](https://eprint.iacr.org/2019/1047.pdf), which uses precomputed commitments to a circuit to be evaluated in a zkSNARK. This seems analogous to our approach of precomputing the aggregate hash for the table used in a homomorphic signature scheme. As we were working on this, we found a similar approach published in 2014 by [Catalano, Fiore, and Warinchi](https://eprint.iacr.org/2014/469.pdf) which they call Homomorphic Signatures with Efficient Verification.  


This library is implemented using the `ark-works` cryptographic ecosystem and provides an extensible trait for other signature schemes that follow a similar design.

---

## How It Works
It is helpful to think of homomorphic signatures as signing a table of data. A signer will sign messages corresponding to the rows of a table, each table must have a unique `tag` to distinguish signatures from other tables. Each row can is assigned a unique index and the message for that row can be signed independently. A signer can sign and send many messages but each one must have a unique index (i.e. row id). A receiver in possesion of many row signatures for a given table can aggregate them into a single signature. This aggregated signature can be verified by a by anyone using the public key of the signer.

At high-level there are 7 main functions in H2S2. 

### 1. **Setup**
This initializes the public parameters for an instance of the protocol

### 2. **Precompute**
This precomputes the hash aggregate value for the specific instance of the protocol. Note that this requires a unique `tag` for every table to be signed.

### 3. **Key Generation**
Calculate the private signing key and the public verification key.

### 4. **Signing Messages**
Creates a signature for a message and an index. 

### 5. **Verifying Signatures**
Ensures that a given signature matches the provided message, index, and public key.

### 6. **Aggregating Signatures (Evaluate)**
`evaluate` combines multiple signatures into a single aggregated signature. It ensures weighted contributions based on the provided weights.

### 7. **Verifying Aggregated Signatures**
Validates the aggregated signature using precomputed hash aggregates and cryptographic parameters.

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

