# iso9796_rsa in Rust


## Usage


Example with non-recoverable part.

Sign:
```rust

// // RSA-1024 key
// let private_key = RsaPrivateKey::read_pkcs8_pem_file("demo_pkcs8.pem")?;

pub fn iso9796_create_signature_nonrecoverable<'a>(
    private_key: &RsaPrivateKey,
    content: &'a [u8],
) -> eyre::Result<(&'a [u8], Vec<u8>)> {
    let mut rng = rand::thread_rng();

    let signing_key = ISO9796SigningKey::<Sha1>::new(Cow::Borrowed(private_key), Trailer::Implicit);

    let (recoverable, signature_bytes) = signing_key
        .generate_signature(Some(&mut rng), content)
        .wrap_err("generate_signature")?;
    assert_ne!(&signature_bytes[..], content);

    let non_recoverable: &[u8] = if recoverable.len() == content.len() {
        &[]
    } else {
        &content[recoverable.len()..]
    };

    Ok((non_recoverable, signature_bytes))
}


pub fn iso9796_verify_signature<PK: PublicKeyParts + Clone>(
    public_key: &PK,
    signature: &[u8],
    unrecoverable: &[u8],
) -> eyre::Result<Vec<u8>> {
    let signing_key =
        ISO9796VerifyingKey::<Sha1, PK>::new(Cow::Borrowed(public_key), Trailer::Implicit);

    let recovered = signing_key
        .verify_signature(signature, unrecoverable)
        .wrap_err("verify_signature")?;

    println!("recovered: {:?}", String::from_utf8_lossy(&recovered));

    Ok(recovered)
}
```