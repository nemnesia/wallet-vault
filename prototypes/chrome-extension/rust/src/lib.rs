use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

type R<T> = Result<T, String>;
const INVALID: &str = "INVALID_INPUT";
const INTEGRITY: &str = "INTEGRITY_FAILED";
const STATE: &str = "INVALID_STATE";
const WRAP_HEADER: usize = 75;
const RECORD_HEADER: usize = 42;
const MAX_INPUT: usize = 4096;

fn require(ok: bool, error: &str) -> R<()> {
    if ok { Ok(()) } else { Err(error.into()) }
}
fn random<const N: usize>() -> R<[u8; N]> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| "RANDOM_FAILED".to_owned())?;
    Ok(value)
}
fn id(bytes: &[u8]) -> R<[u8; 16]> {
    bytes.try_into().map_err(|_| INVALID.into())
}
fn label_ok(label: &str) -> R<()> {
    require(!label.is_empty() && label.len() <= 64, INVALID)
}
fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
fn header(profile: &[u8; 16], kind: u8, object: &[u8; 16], wrap: bool) -> Vec<u8> {
    let mut value = join(&[b"VPC1", &[1], profile]);
    if wrap {
        value.push(1);
    }
    value.push(kind);
    value.extend_from_slice(object);
    value.extend_from_slice(&1u32.to_be_bytes());
    value
}
fn validate_header(bytes: &[u8], profile: &[u8; 16], purpose: u8, wrap: bool) -> R<()> {
    require(bytes.len() <= MAX_INPUT, INVALID)?;
    let minimum = if wrap {
        WRAP_HEADER + 60
    } else {
        RECORD_HEADER + 32
    };
    require(bytes.len() >= minimum, INVALID)?;
    require(&bytes[..5] == b"VPC1\x01", INVALID)?;
    require(&bytes[5..21] == profile, INVALID)?;
    let purpose_offset = if wrap { 22 } else { 21 };
    if wrap {
        require(bytes[21] == 1, INVALID)?;
    }
    require(bytes[purpose_offset] == purpose, INVALID)?;
    require(
        bytes[purpose_offset + 17..purpose_offset + 21] == 1u32.to_be_bytes(),
        INVALID,
    )
}
fn kek(
    prf: &[u8],
    profile: &[u8; 16],
    purpose: u8,
    wrap_id: &[u8],
    salt: &[u8],
) -> R<Zeroizing<[u8; 32]>> {
    require(prf.len() == 32, INVALID)?;
    let prf = Zeroizing::new(prf.to_vec());
    let info = join(&[
        b"vault-prototype/kek/v1",
        profile,
        &[1, purpose],
        wrap_id,
        &1u32.to_be_bytes(),
    ]);
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), &prf)
        .expand(&info, &mut *key)
        .map_err(|_| "INTERNAL_ERROR".to_owned())?;
    Ok(key)
}
fn encrypt(key: &[u8], nonce: &[u8], plain: &[u8], aad: &[u8]) -> R<Vec<u8>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| INVALID.to_owned())?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| "INTERNAL_ERROR".into())
}
fn decrypt(key: &[u8], nonce: &[u8], cipher: &[u8], aad: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| INVALID.to_owned())?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: cipher, aad })
        .map(Zeroizing::new)
        .map_err(|_| INTEGRITY.into())
}
fn wrap(profile: &[u8; 16], purpose: u8, prf: &[u8], dek: &[u8]) -> R<Vec<u8>> {
    let wrap_id = random::<16>()?;
    let salt = random::<32>()?;
    let nonce = random::<12>()?;
    let mut h = header(profile, purpose, &wrap_id, true);
    h.extend_from_slice(&salt);
    let key = kek(prf, profile, purpose, &wrap_id, &salt)?;
    let aad = join(&[b"vault-prototype/wrap/v1", &h]);
    let ciphertext = encrypt(key.as_ref(), &nonce, dek, &aad)?;
    Ok(join(&[&h, &nonce, &ciphertext]))
}
fn unwrap(profile: &[u8; 16], purpose: u8, prf: &[u8], bytes: &[u8]) -> R<Zeroizing<Vec<u8>>> {
    validate_header(bytes, profile, purpose, true)?;
    require(bytes.len() == WRAP_HEADER + 60, INVALID)?;
    let key = kek(prf, profile, purpose, &bytes[23..39], &bytes[43..75])?;
    let aad = join(&[b"vault-prototype/wrap/v1", &bytes[..WRAP_HEADER]]);
    decrypt(key.as_ref(), &bytes[75..87], &bytes[87..], &aad)
}
fn record_aad(h: &[u8], label: Option<&str>) -> Vec<u8> {
    let mut aad = join(&[b"vault-prototype/record/v1", h]);
    if let Some(label) = label {
        aad.extend_from_slice(&(label.len() as u32).to_be_bytes());
        aad.extend_from_slice(label.as_bytes());
    }
    aad
}
fn seal(
    profile: &[u8; 16],
    purpose: u8,
    key: &[u8],
    plain: &[u8],
    label: Option<&str>,
) -> R<Vec<u8>> {
    let h = header(profile, purpose, &random::<16>()?, false);
    let nonce = random::<12>()?;
    let cipher = encrypt(key, &nonce, plain, &record_aad(&h, label))?;
    Ok(join(&[
        &h,
        &nonce,
        &(plain.len() as u32).to_be_bytes(),
        &cipher,
    ]))
}
fn unseal(
    profile: &[u8; 16],
    purpose: u8,
    key: &[u8],
    bytes: &[u8],
    label: Option<&str>,
) -> R<Zeroizing<Vec<u8>>> {
    validate_header(bytes, profile, purpose, false)?;
    let plain_length =
        u32::from_be_bytes(bytes[54..58].try_into().map_err(|_| INVALID.to_owned())?) as usize;
    let expected = if purpose == 1 { 64 } else { 32 };
    require(
        plain_length == expected && bytes.len() == 58 + plain_length + 16,
        INVALID,
    )?;
    decrypt(
        key,
        &bytes[42..54],
        &bytes[58..],
        &record_aad(&bytes[..RECORD_HEADER], label),
    )
}

#[wasm_bindgen]
pub struct EncryptedBundle {
    profile_wrap: Vec<u8>,
    signing_wrap: Vec<u8>,
    profile_record: Vec<u8>,
    signing_record: Vec<u8>,
}
#[wasm_bindgen]
impl EncryptedBundle {
    pub fn profile_wrap(&self) -> Vec<u8> {
        self.profile_wrap.clone()
    }
    pub fn signing_wrap(&self) -> Vec<u8> {
        self.signing_wrap.clone()
    }
    pub fn profile_record(&self) -> Vec<u8> {
        self.profile_record.clone()
    }
    pub fn signing_record(&self) -> Vec<u8> {
        self.signing_record.clone()
    }
}

#[wasm_bindgen]
pub struct Registration {
    profile: [u8; 16],
    label: String,
    profile_dek: Option<Zeroizing<[u8; 32]>>,
    profile_wrap: Option<Vec<u8>>,
}
#[wasm_bindgen]
impl Registration {
    #[wasm_bindgen(constructor)]
    pub fn new(label: &str) -> R<Registration> {
        label_ok(label)?;
        Ok(Self {
            profile: random()?,
            label: label.to_owned(),
            profile_dek: None,
            profile_wrap: None,
        })
    }
    pub fn profile_id(&self) -> Vec<u8> {
        self.profile.to_vec()
    }
    pub fn accept_profile_prf(&mut self, prf: &[u8]) -> R<()> {
        require(self.profile_wrap.is_none(), STATE)?;
        let dek = Zeroizing::new(random::<32>()?);
        let wrapped = wrap(&self.profile, 1, prf, dek.as_ref())?;
        self.profile_dek = Some(dek);
        self.profile_wrap = Some(wrapped);
        Ok(())
    }
    pub fn finish(&mut self, prf: &[u8]) -> R<EncryptedBundle> {
        let profile_dek = self.profile_dek.take().ok_or(STATE)?;
        let profile_wrap = self.profile_wrap.take().ok_or(STATE)?;
        let signing_dek = Zeroizing::new(random::<32>()?);
        let signing_probe = Zeroizing::new(random::<32>()?);
        let mut profile_plain = Zeroizing::new(random::<64>()?);
        profile_plain[32..].copy_from_slice(&Sha256::digest(signing_probe.as_ref()));
        Ok(EncryptedBundle {
            profile_wrap,
            signing_wrap: wrap(&self.profile, 2, prf, signing_dek.as_ref())?,
            profile_record: seal(
                &self.profile,
                1,
                profile_dek.as_ref(),
                profile_plain.as_ref(),
                Some(&self.label),
            )?,
            signing_record: seal(
                &self.profile,
                2,
                signing_dek.as_ref(),
                signing_probe.as_ref(),
                None,
            )?,
        })
    }
}

struct Request {
    id: Vec<u8>,
    deadline: f64,
}
#[wasm_bindgen]
pub struct VaultSession {
    profile: [u8; 16],
    label: String,
    bundle: EncryptedBundle,
    profile_dek: Option<Zeroizing<Vec<u8>>>,
    digest: Option<Zeroizing<[u8; 32]>>,
    pending: Option<Request>,
    active: Option<Request>,
}
#[wasm_bindgen]
impl VaultSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        profile: &[u8],
        label: &str,
        profile_wrap: &[u8],
        signing_wrap: &[u8],
        profile_record: &[u8],
        signing_record: &[u8],
    ) -> R<VaultSession> {
        label_ok(label)?;
        let profile = id(profile)?;
        for (value, purpose, wrapped) in [
            (profile_wrap, 1, true),
            (signing_wrap, 2, true),
            (profile_record, 1, false),
            (signing_record, 2, false),
        ] {
            validate_header(value, &profile, purpose, wrapped)?;
        }
        Ok(Self {
            profile,
            label: label.to_owned(),
            bundle: EncryptedBundle {
                profile_wrap: profile_wrap.to_vec(),
                signing_wrap: signing_wrap.to_vec(),
                profile_record: profile_record.to_vec(),
                signing_record: signing_record.to_vec(),
            },
            profile_dek: None,
            digest: None,
            pending: None,
            active: None,
        })
    }
    pub fn open(&mut self, prf: &[u8]) -> R<()> {
        require(self.profile_dek.is_none(), STATE)?;
        let key = unwrap(&self.profile, 1, prf, &self.bundle.profile_wrap)?;
        let plain = unseal(
            &self.profile,
            1,
            &key,
            &self.bundle.profile_record,
            Some(&self.label),
        )?;
        let mut digest = Zeroizing::new([0; 32]);
        digest.copy_from_slice(&plain[32..]);
        self.digest = Some(digest);
        self.profile_dek = Some(key);
        Ok(())
    }
    pub fn prepare(&mut self, now: f64) -> R<Vec<u8>> {
        require(
            self.profile_dek.is_some() && now.is_finite() && now >= 0.,
            STATE,
        )?;
        require(self.pending.is_none() && self.active.is_none(), "BUSY")?;
        let request_id = random::<16>()?.to_vec();
        self.pending = Some(Request {
            id: request_id.clone(),
            deadline: now + 60000.,
        });
        Ok(request_id)
    }
    pub fn begin(&mut self, request_id: &[u8], now: f64) -> R<()> {
        require(self.active.is_none(), "BUSY")?;
        // Consume before validation: even a failed attempt cannot retry this request.
        let request = self.pending.take().ok_or(STATE)?;
        require(request.id == request_id, STATE)?;
        require(
            now.is_finite() && now >= 0. && now < request.deadline,
            "EXPIRED",
        )?;
        self.active = Some(request);
        Ok(())
    }
    pub fn finish(&mut self, prf: &[u8], now: f64) -> R<bool> {
        let request = self.active.take().ok_or(STATE)?;
        require(
            now.is_finite() && now >= 0. && now < request.deadline,
            "EXPIRED",
        )?;
        let expected = self.digest.as_ref().ok_or(STATE)?;
        let key = unwrap(&self.profile, 2, prf, &self.bundle.signing_wrap)?;
        let plain = unseal(&self.profile, 2, &key, &self.bundle.signing_record, None)?;
        let mut digest = Sha256::digest(&plain);
        let matched = bool::from(digest.as_slice().ct_eq(expected.as_ref()));
        digest.as_mut_slice().zeroize();
        require(matched, INTEGRITY)?;
        Ok(true)
    }
    pub fn cancel(&mut self) {
        self.pending = None;
        self.active = None;
    }
    pub fn lock(&mut self) {
        self.cancel();
        self.profile_dek = None;
        self.digest = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Registration, EncryptedBundle) {
        let mut registration = Registration::new("test").unwrap();
        registration.accept_profile_prf(&[1; 32]).unwrap();
        let bundle = registration.finish(&[2; 32]).unwrap();
        (registration, bundle)
    }
    fn session(reg: &Registration, bundle: &EncryptedBundle, label: &str) -> VaultSession {
        VaultSession::new(
            &reg.profile_id(),
            label,
            &bundle.profile_wrap,
            &bundle.signing_wrap,
            &bundle.profile_record,
            &bundle.signing_record,
        )
        .unwrap()
    }
    #[test]
    fn roundtrip_is_purpose_separated_and_single_use() {
        let (reg, bundle) = fixture();
        let mut s = session(&reg, &bundle, "test");
        assert!(s.open(&[2; 32]).is_err());
        s.open(&[1; 32]).unwrap();
        let request = s.prepare(10.).unwrap();
        assert!(s.prepare(11.).is_err());
        s.begin(&request, 12.).unwrap();
        assert!(s.begin(&request, 13.).is_err());
        assert!(s.finish(&[2; 32], 14.).unwrap());
        assert!(s.finish(&[2; 32], 15.).is_err());
        assert!(s.begin(&request, 16.).is_err());
    }
    #[test]
    fn cancel_lock_expiry_and_wrong_key_consume_requests() {
        let (reg, bundle) = fixture();
        let mut s = session(&reg, &bundle, "test");
        s.open(&[1; 32]).unwrap();
        let request = s.prepare(1.).unwrap();
        assert_eq!(s.begin(&request, 60001.), Err("EXPIRED".into()));
        assert!(s.begin(&request, 2.).is_err());
        let request = s.prepare(10.).unwrap();
        s.begin(&request, 11.).unwrap();
        assert!(s.finish(&[1; 32], 12.).is_err());
        assert!(s.finish(&[2; 32], 13.).is_err());
        let request = s.prepare(20.).unwrap();
        s.begin(&request, 21.).unwrap();
        s.cancel();
        assert!(s.finish(&[2; 32], 22.).is_err());
        let request = s.prepare(30.).unwrap();
        s.lock();
        assert!(s.begin(&request, 31.).is_err());
        assert!(s.prepare(32.).is_err());
    }
    #[test]
    fn rejects_tampering_label_wrong_profile_truncation_and_extra_bytes() {
        let (reg, mut bundle) = fixture();
        assert!(session(&reg, &bundle, "changed").open(&[1; 32]).is_err());
        let (other, _) = fixture();
        assert!(
            VaultSession::new(
                &other.profile_id(),
                "test",
                &bundle.profile_wrap,
                &bundle.signing_wrap,
                &bundle.profile_record,
                &bundle.signing_record
            )
            .is_err()
        );
        for offset in 0..bundle.profile_wrap.len() {
            let mut changed = bundle.profile_wrap.clone();
            changed[offset] ^= 1;
            assert!(unwrap(&reg.profile, 1, &[1; 32], &changed).is_err());
        }
        for length in 0..bundle.profile_record.len() {
            assert!(
                unseal(
                    &reg.profile,
                    1,
                    &[0; 32],
                    &bundle.profile_record[..length],
                    Some("test")
                )
                .is_err()
            );
        }
        bundle.profile_wrap.push(0);
        assert!(session(&reg, &bundle, "test").open(&[1; 32]).is_err());
    }
    #[test]
    fn shared_standard_vectors() {
        // RFC 5869 A.1; public synthetic inputs, no captured credential material.
        let mut out = [0; 42];
        Hkdf::<Sha256>::new(Some(&(0..13).collect::<Vec<_>>()), &[0x0b; 22])
            .expand(&(0xf0..=0xf9).collect::<Vec<_>>(), &mut out)
            .unwrap();
        assert_eq!(
            out.as_slice(),
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
        // NIST AES-256-GCM, all-zero key/IV, empty plaintext/AAD.
        assert_eq!(
            encrypt(&[0; 32], &[0; 12], &[], &[]).unwrap(),
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b
            ]
        );
        assert_eq!(header(&[0; 16], 1, &[0; 16], false).len(), RECORD_HEADER);
        assert_eq!(header(&[0; 16], 1, &[0; 16], true).len() + 32, WRAP_HEADER);
    }
}
