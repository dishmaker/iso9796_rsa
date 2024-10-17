use std::borrow::Cow;

use eyre::Context;
use rand::thread_rng;
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use sha1::Sha1;

use crate::iso9796::{ISO9796SigningKey, ISO9796VerifyingKey, Trailer};

#[test]
pub fn sign_verify_1024() {
    // RSA-1024 key
    let bits = 1024;
    let mut rng = thread_rng();

    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    let input = vec![b'A'; 31];
    let signature = iso9796_create_signature(&priv_key, &input).unwrap();

    assert_eq!(signature.len(), 128);

    let recovered = iso9796_verify_signature(priv_key.to_public_key(), &signature, &[]).unwrap();

    assert_eq!(input, recovered);
}

#[test]
pub fn sign_verify_2048() {
    let bits = 2048;
    let mut rng = thread_rng();

    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    let input = vec![b'B'; 31];
    let signature = iso9796_create_signature(&priv_key, &input).unwrap();

    assert_eq!(signature.len(), 256);

    let recovered = iso9796_verify_signature(priv_key.to_public_key(), &signature, &[]).unwrap();

    assert_eq!(input, recovered);
}

#[test]
pub fn sign_verify_recover_1024() {
    // RSA-1024 key
    let bits = 1024;
    let mut rng = thread_rng();

    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    let input = vec![b'A'; 123];
    let (unrecoverable, signature) =
        iso9796_create_signature_nonrecoverable(&priv_key, &input).unwrap();

    assert_eq!(signature.len(), 128);

    let recovered =
        iso9796_verify_signature(priv_key.to_public_key(), &signature, unrecoverable).unwrap();

    assert_eq!(input, [&recovered, unrecoverable].concat());
}

pub fn iso9796_create_signature(
    private_key: &RsaPrivateKey,
    content: &[u8],
) -> eyre::Result<Vec<u8>> {
    let (_, signature_bytes) = iso9796_create_signature_nonrecoverable(private_key, content)?;

    Ok(signature_bytes)
}

pub fn iso9796_create_signature_nonrecoverable<'a>(
    private_key: &RsaPrivateKey,
    content: &'a [u8],
) -> eyre::Result<(&'a [u8], Vec<u8>)> {
    let mut rng = rand::thread_rng();

    let signing_key =
        ISO9796SigningKey::<Sha1, _>::new(Cow::Borrowed(private_key), Trailer::Implicit);

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
    public_key: PK,
    signature: &[u8],
    unrecoverable: &[u8],
) -> eyre::Result<Vec<u8>> {
    let signing_key = ISO9796VerifyingKey::<Sha1, PK>::new(public_key, Trailer::Implicit);

    let recovered = signing_key
        .verify_signature(signature, unrecoverable)
        .wrap_err("verify_signature")?;

    println!("recovered: {:?}", String::from_utf8_lossy(&recovered));

    Ok(recovered)
}
