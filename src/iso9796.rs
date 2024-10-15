use std::{borrow::Cow, marker::PhantomData};

use eyre::ensure;
use eyre::eyre;
use eyre::OptionExt;
use rsa::traits::PublicKeyParts;
use rsa::{
    hazmat::{rsa_decrypt, rsa_encrypt},
    rand_core::CryptoRngCore,
    BigUint, RsaPrivateKey,
};
use sha1::Digest;

use crate::hexslice::HexDisplay;
use crate::pad::uint_to_be_pad;

///! based on https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/signers/ISO9796d2Signer.java

const TRAILER_IMPLICIT: u8 = 0xBC;

#[derive(Debug, Clone)]
pub struct ISO9796SigningKey<'k, D>
where
    D: Digest,
{
    inner: Cow<'k, RsaPrivateKey>,
    trailer: Trailer,
    block_len: u16,
    phantom: PhantomData<D>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Trailer {
    Implicit,
    Explicit(u16),
}

impl<'k, D: Digest> ISO9796SigningKey<'k, D> {
    pub fn new(key: Cow<'k, RsaPrivateKey>, trailer: Trailer) -> ISO9796SigningKey<'k, D> {
        use rsa::traits::PublicKeyParts;

        let key_bits = key.n().bits();
        let block_len = (key_bits + 7) / 8;
        ISO9796SigningKey {
            inner: key,
            trailer: trailer,
            block_len: block_len as u16,
            phantom: Default::default(),
        }
    }

    pub fn block_len(&self) -> u16 {
        self.block_len
    }

    pub fn generate_padded<'a>(&self, message: &'a [u8]) -> eyre::Result<(&'a [u8], Vec<u8>)> {
        let mut block: Vec<u8> = vec![0xFF; self.block_len as usize];

        let dig_size = <D as Digest>::output_size();

        let digested = D::digest(message);

        let (t, delta) = if let Trailer::Explicit(trailer) = self.trailer {
            let delta = block.len() - dig_size - 2;
            block[delta..(delta + dig_size)].copy_from_slice(&digested);
            block[self.block_len as usize - 2] = (trailer >> 8) as u8;
            block[self.block_len as usize - 1] = (trailer & 0xff) as u8;
            (16, delta)
        } else {
            let delta = block.len() - dig_size - 1;
            block[delta..(delta + dig_size)].copy_from_slice(&digested);
            block[self.block_len as usize - 1] = TRAILER_IMPLICIT;
            (8, delta)
        };
        let key_bits = {
            use rsa::traits::PublicKeyParts;
            self.inner.n().bits()
        };
        let bits = (dig_size + message.len()) * 8 + t + 4 - key_bits;

        let is_full_message = bits > 0;

        let header = if is_full_message { 0x60 } else { 0x40 };

        let (delta, recoverable) = if is_full_message {
            let mr = message.len() - ((bits + 7) / 8);

            let delta = delta - mr;

            let recoverable = &message[0..mr];
            block[delta..(delta + mr)].copy_from_slice(recoverable);

            (delta, recoverable)
        } else {
            let delta = delta - message.len();

            let recoverable = &message[..];
            block[delta..(delta + message.len())].copy_from_slice(recoverable);

            (delta, recoverable)
        };

        if (delta - 1) > 0 {
            block[1..=(delta - 1)].fill(0xBB);
            block[delta - 1] ^= 0x01;
            block[0] = 0x0b;
            block[0] |= header;
        } else {
            // 6A or 4A  when message took too much space
            block[0] = 0x0a;
            block[0] |= header;
        }

        Ok((recoverable, block))
    }

    pub fn generate_signature<'a, R: CryptoRngCore + ?Sized>(
        &self,
        blinding_rng: Option<&mut R>,
        message: &'a [u8],
    ) -> eyre::Result<(&'a [u8], Vec<u8>)> {
        let (recoverable, mut to_encrypt) = self.generate_padded(message)?;
        //let encrypted = rsa_encrypt(&self.inner, &BigUint::from_bytes_be(&to_encrypt))?;

        // signature uses the decrypt function, but it encrypts (because the private key is needed)
        let encrypted = rsa_decrypt(
            blinding_rng,
            self.inner.as_ref(),
            &BigUint::from_bytes_be(&to_encrypt),
        )?;

        to_encrypt.fill(0);

        use rsa::traits::PublicKeyParts;
        let encrypted = uint_to_be_pad(encrypted, self.inner.size())?;
        Ok((recoverable, encrypted))
    }
}

#[derive(Clone)]
pub struct ISO9796VerifyingKey<'k, D, PK>
where
    D: Digest,
    PK: PublicKeyParts + Clone,
{
    inner: Cow<'k, PK>,

    trailer: Trailer,
    block_len: u16,
    phantom: PhantomData<D>,
}

impl<'k, D, PK> ISO9796VerifyingKey<'k, D, PK>
where
    D: Digest,
    PK: PublicKeyParts + Clone,
{
    pub fn new(key: Cow<'k, PK>, trailer: Trailer) -> ISO9796VerifyingKey<'k, D, PK> {
        let key_bits = key.n().bits();

        let block_len = (key_bits + 7) / 8;

        ISO9796VerifyingKey {
            inner: key,
            trailer: trailer,
            block_len: block_len as u16,
            phantom: Default::default(),
        }
    }
    ///
    /// find out how much padding we've got
    ///
    pub fn find_message_start(&self, plain_signature: &[u8]) -> usize {
        let mut m_start = 0;

        while m_start < plain_signature.len() {
            if ((plain_signature[m_start] & 0x0f) ^ 0x0a) == 0 {
                break;
            }
            m_start += 1;
        }

        m_start + 1
    }

    pub fn verify_signature(
        &self,
        signature: &[u8],
        unrecoverable: &[u8],
    ) -> eyre::Result<Vec<u8>> {
        let expected_block_len = self.block_len as usize;
        ensure!(signature.len() == expected_block_len);

        let signature = rsa_encrypt(self.inner.as_ref(), &BigUint::from_bytes_be(&signature))?;
        let signature: Vec<u8> = signature.to_bytes_be();

        ensure!(signature.len() == expected_block_len);

        let first_byte = signature
            .first()
            .cloned()
            .ok_or_eyre("can't get first byte")?;

        if (first_byte & 0xC0) ^ 0x40 != 0 {
            return Err(eyre!("wrong signature: (first_byte & 0xC0) ^ 0x40 != 0"));
        }

        let last_byte = signature
            .last()
            .cloned()
            .ok_or_eyre("can't get last byte")?;
        if (last_byte & 0xF) ^ 0xC != 0 {
            return Err(eyre!("wrong signature: (last_byte & 0xF) ^ 0xC != 0"));
        }

        let trailer_implicit = last_byte == 0xBC;
        let trailer_len = if trailer_implicit { 1 } else { 2 };

        let trailer = if trailer_implicit {
            Trailer::Implicit
        } else {
            let sig_trail =
                u16::from_be_bytes(signature[signature.len() - 2..].try_into().unwrap());

            Trailer::Explicit(sig_trail)
        };
        if trailer != self.trailer {
            return Err(eyre!("unexpected trailer: {trailer:?}"));
        }

        let m_start = self.find_message_start(&signature);

        let dig_size = <D as Digest>::output_size();
        //
        // check the hashes
        //
        let digest_offset = signature.len() - trailer_len - dig_size;

        //
        // there must be at least one byte of message string
        //
        if digest_offset <= m_start {
            return Err(eyre!("message too short: {digest_offset} <= {m_start}"));
        }

        let full_message = signature[0] & 0x20 == 0;

        let recovered_message = signature
            .get(m_start..digest_offset)
            .ok_or_else(|| eyre!("signature message not in range {m_start}..{digest_offset}"))?;

        let mut d = D::new();

        d.update(&recovered_message);

        if full_message {
            if !unrecoverable.is_empty() {
                return Err(eyre!("full_message, but unrecoverable is not empty"));
            }
        } else {
            d.update(unrecoverable);
        }

        let computed_hash = d.finalize();

        let signature_hash = &signature[digest_offset..digest_offset + computed_hash.len()];
        let computed_hash = &computed_hash[..];

        if computed_hash != signature_hash {
            return Err(eyre!(
                "wrong hash: computed_hash != signature_hash, {} != {}",
                HexDisplay(computed_hash),
                HexDisplay(signature_hash)
            ));
        }

        Ok(recovered_message.to_vec())
    }
}
