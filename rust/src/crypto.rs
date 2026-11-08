use crate::{Error, Result, model::Key};
use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::RandomFailure)?;
    Ok(bytes)
}
pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Key> {
    // RFC 5869 Extract followed by the single Expand block needed for L=32.
    // Keep PRK and T(1) under explicit zeroization instead of leaving byte-array
    // outputs from a generic HKDF implementation alive after return.
    let mut extract =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(salt).map_err(|_| Error::InternalFailure)?;
    extract.update(ikm);
    let mut prk = extract.finalize().into_bytes();
    let mut expand =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&prk).map_err(|_| Error::InternalFailure)?;
    prk.zeroize();
    expand.update(info);
    expand.update(&[1]);
    let mut block = expand.finalize().into_bytes();
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&block);
    block.zeroize();
    Ok(key)
}

pub(crate) fn password(password: &[u8], salt: &[u8]) -> Result<Key> {
    crate::format::sized(password, 1, 1024)?;
    std::str::from_utf8(password).map_err(|_| Error::InvalidInput)?;
    if salt.len() != 16 {
        return Err(Error::InvalidInput);
    }
    let params = Params::new(65_536, 3, 4, Some(32)).map_err(|_| Error::InternalFailure)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // The operation reserves this heap plus a conservative auxiliary bound before entry.
    // Explicit workspace avoids the KDF allocating an unaccounted second region.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(65_536)
        .map_err(|_| Error::ResourceLimit)?;
    memory.resize(65_536, Block::default());
    let mut output = Zeroizing::new([0; 32]);
    let result = argon.hash_password_into_with_memory(password, salt, &mut *output, &mut memory);
    for block in memory.iter_mut() {
        block.zeroize();
    }
    result.map_err(|_| Error::InternalFailure)?;
    Ok(output)
}
pub(crate) fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidInput)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + 16));
    buffer.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), aad, &mut buffer)
        .map_err(|_| Error::InternalFailure)?;
    buffer.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *buffer))
}
pub(crate) fn open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != 12 || ciphertext.len() < 16 {
        return Err(Error::InvalidInput);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidInput)?;
    let n = ciphertext.len() - 16;
    let mut buffer = Zeroizing::new(ciphertext[..n].to_vec());
    cipher
        .decrypt_in_place_detached(nonce.into(), aad, &mut buffer, ciphertext[n..].into())
        .map_err(|_| Error::VerificationFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_vectors() {
        // RFC 5869 test case 1, SHA-256, truncated to the library's 32-byte output.
        let k = hkdf(
            &[0x0b; 22],
            &hex::decode("000102030405060708090a0b0c").unwrap(),
            &hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
        )
        .unwrap();
        assert!(
            *k == hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
                .unwrap()
                .as_slice()
        );
        // NIST AES-256-GCM, all-zero key/IV, empty plaintext and AAD.
        assert!(
            seal(&[0; 32], &[0; 12], &[], &[]).unwrap()
                == hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap()
        );
        let values = include_str!("../tests/fixtures/v1.txt");
        let get = |key: &str| {
            hex::decode(
                values
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{key}=")))
                    .unwrap(),
            )
            .unwrap()
        };
        let data = get("data");
        let d = crate::format::data(&data).unwrap();
        let c = crate::Context {
            target: d.target.to_vec(),
            purpose: d.purpose.to_vec(),
            generation: d.generation,
        };
        let k = hkdf(
            &get("dek"),
            d.salt,
            &crate::operation::info(&c, None).unwrap(),
        )
        .unwrap();
        assert!(*open(&*k, d.nonce, d.aad, d.ciphertext).unwrap() == get("plaintext"));
        assert!(seal(&*k, d.nonce, d.aad, &get("plaintext")).unwrap() == d.ciphertext);
        let raw = get("recovery_wrap");
        let w = crate::format::wrap(&raw).unwrap();
        let k = hkdf(
            &get("recovery"),
            w.salt,
            &crate::operation::info(&c, Some((w.route, 3))).unwrap(),
        )
        .unwrap();
        assert!(*open(&*k, w.nonce, w.aad, w.ciphertext).unwrap() == get("dek"));
        assert!(
            *password(&get("password"), &get("password_salt")).unwrap()
                == get("argon2id").as_slice()
        );
    }
}
