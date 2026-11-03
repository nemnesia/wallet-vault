use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{LazyLock, Mutex};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type R<T> = Result<T, &'static str>;
fn check(ok: bool, code: &'static str) -> R<()> {
    if ok { Ok(()) } else { Err(code) }
}
fn random<const N: usize>() -> R<[u8; N]> {
    let mut b = [0; N];
    getrandom::fill(&mut b).map_err(|_| "RANDOM_FAILED")?;
    Ok(b)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|n| format!("{n:02x}")).collect()
}
fn bytes(s: &str, max: usize) -> R<Vec<u8>> {
    check(
        s.len() <= max * 2 && s.len().is_multiple_of(2),
        "INVALID_INPUT",
    )?;
    check(
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "INVALID_INPUT",
    )?;
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let n = |v: u8| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
            Ok(n(p[0]) * 16 + n(p[1]))
        })
        .collect()
}
fn profile(s: &str) -> R<[u8; 16]> {
    bytes(s, 16)?.try_into().map_err(|_| "INVALID_INPUT")
}
fn label(s: &str) -> R<()> {
    check(!s.is_empty() && s.len() <= 64, "INVALID_INPUT")
}
fn header(id: &[u8; 16], purpose: u8) -> R<Vec<u8>> {
    Ok([
        b"VMI1".as_slice(),
        &[purpose],
        id,
        &1u32.to_be_bytes(),
        &random::<16>()?,
    ]
    .concat())
}
fn aad(h: &[u8], name: &str) -> Vec<u8> {
    [
        b"vault-ios/record/v1".as_slice(),
        h,
        &(name.len() as u32).to_be_bytes(),
        name.as_bytes(),
    ]
    .concat()
}
fn seal(id: &[u8; 16], purpose: u8, key: &[u8], plain: &[u8], name: &str) -> R<Vec<u8>> {
    let h = header(id, purpose)?;
    let nonce = random::<12>()?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "INVALID_INPUT")?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad(&h, name),
            },
        )
        .map_err(|_| "INTERNAL_ERROR")?;
    Ok([
        h,
        nonce.to_vec(),
        (plain.len() as u32).to_be_bytes().to_vec(),
        cipher,
    ]
    .concat())
}
fn validate_record(id: &[u8; 16], purpose: u8, b: &[u8]) -> R<()> {
    let length = if purpose == 1 { 64 } else { 32 };
    check(
        b.len() == 57 + length + 16 && b.len() <= 4096,
        "INVALID_INPUT",
    )?;
    check(
        &b[..4] == b"VMI1" && b[4] == purpose && b[5..21] == *id && b[21..25] == 1u32.to_be_bytes(),
        "INVALID_INPUT",
    )?;
    check(b[53..57] == (length as u32).to_be_bytes(), "INVALID_INPUT")
}
fn unseal(id: &[u8; 16], purpose: u8, key: &[u8], b: &[u8], name: &str) -> R<Zeroizing<Vec<u8>>> {
    validate_record(id, purpose, b)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "INVALID_INPUT")?
        .decrypt(
            Nonce::from_slice(&b[41..53]),
            Payload {
                msg: &b[57..],
                aad: &aad(&b[..41], name),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| "INTEGRITY_FAILED")
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Records {
    id: String,
    label: String,
    profile_record: String,
    signing_record: String,
}
impl Records {
    fn validate(&self) -> R<()> {
        let id = profile(&self.id)?;
        label(&self.label)?;
        validate_record(&id, 1, &bytes(&self.profile_record, 4096)?)?;
        validate_record(&id, 2, &bytes(&self.signing_record, 4096)?)
    }
}
struct Registration {
    records: Records,
    profile_key: Zeroizing<[u8; 32]>,
    signing_key: Zeroizing<[u8; 32]>,
}
impl Registration {
    fn new(name: &str) -> R<Self> {
        label(name)?;
        let id = random::<16>()?;
        let profile_key = Zeroizing::new(random::<32>()?);
        let signing_key = Zeroizing::new(random::<32>()?);
        let signing_plain = Zeroizing::new(random::<32>()?);
        let mut plain = Zeroizing::new(random::<64>()?);
        plain[32..].copy_from_slice(&Sha256::digest(signing_plain.as_ref()));
        Ok(Self {
            records: Records {
                id: hex(&id),
                label: name.into(),
                profile_record: hex(&seal(&id, 1, profile_key.as_ref(), plain.as_ref(), name)?),
                signing_record: hex(&seal(
                    &id,
                    2,
                    signing_key.as_ref(),
                    signing_plain.as_ref(),
                    name,
                )?),
            },
            profile_key,
            signing_key,
        })
    }
}
struct Request {
    id: String,
    deadline: u64,
}
struct Session {
    records: Records,
    _profile_key: Zeroizing<Vec<u8>>,
    digest: Zeroizing<[u8; 32]>,
    pending: Option<Request>,
    active: Option<Request>,
}
impl Session {
    fn open(records: Records, key: &[u8]) -> R<Self> {
        records.validate()?;
        let plain = unseal(
            &profile(&records.id)?,
            1,
            key,
            &bytes(&records.profile_record, 4096)?,
            &records.label,
        )?;
        let mut digest = Zeroizing::new([0; 32]);
        digest.copy_from_slice(&plain[32..]);
        Ok(Self {
            records,
            _profile_key: Zeroizing::new(key.to_vec()),
            digest,
            pending: None,
            active: None,
        })
    }
    fn prepare(&mut self, now: u64) -> R<String> {
        check(self.pending.is_none() && self.active.is_none(), "BUSY")?;
        let id = hex(&random::<16>()?);
        self.pending = Some(Request {
            id: id.clone(),
            deadline: now.checked_add(60000).ok_or("INVALID_INPUT")?,
        });
        Ok(id)
    }
    fn begin(&mut self, id: &str, now: u64) -> R<()> {
        check(self.active.is_none(), "BUSY")?;
        let request = self.pending.take().ok_or("INVALID_STATE")?;
        check(request.id == id, "INVALID_STATE")?;
        check(now < request.deadline, "EXPIRED")?;
        self.active = Some(request);
        Ok(())
    }
    fn finish(&mut self, key: &[u8], now: u64) -> R<()> {
        let request = self.active.take().ok_or("INVALID_STATE")?;
        check(now < request.deadline, "EXPIRED")?;
        let plain = unseal(
            &profile(&self.records.id)?,
            2,
            key,
            &bytes(&self.records.signing_record, 4096)?,
            &self.records.label,
        )?;
        let mut digest = Sha256::digest(&plain);
        let matched = bool::from(digest.as_slice().ct_eq(self.digest.as_ref()));
        digest.as_mut_slice().zeroize();
        check(matched, "INTEGRITY_FAILED")
    }
    fn cancel(&mut self) {
        self.pending = None;
        self.active = None;
    }
}
#[derive(Default)]
struct State {
    registration: Option<Registration>,
    session: Option<Session>,
}
fn text<'a>(v: &'a Value, key: &str) -> R<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or("INVALID_INPUT")
}
fn now(v: &Value) -> R<u64> {
    v.get("now").and_then(Value::as_u64).ok_or("INVALID_INPUT")
}
impl State {
    fn command(&mut self, action: &str, data: &str, secret: &[u8]) -> R<String> {
        check(
            data.len() <= 32768 && (secret.is_empty() || secret.len() == 32),
            "INVALID_INPUT",
        )?;
        let v: Value = serde_json::from_str(data).map_err(|_| "INVALID_INPUT")?;
        let result = match action {
            "start" => {
                check(
                    self.registration.is_none() && self.session.is_none(),
                    "INVALID_STATE",
                )?;
                let reg = Registration::new(text(&v, "label")?)?;
                let result = serde_json::to_value(&reg.records).map_err(|_| "INTERNAL_ERROR")?;
                self.registration = Some(reg);
                result
            }
            "registration" => {
                serde_json::to_value(&self.registration.as_ref().ok_or("INVALID_STATE")?.records)
                    .map_err(|_| "INTERNAL_ERROR")?
            }
            "validate" => {
                let records: Records = serde_json::from_value(v).map_err(|_| "INVALID_INPUT")?;
                records.validate()?;
                json!({"valid":true})
            }
            "open" => {
                check(
                    self.session.is_none() && self.registration.is_none(),
                    "INVALID_STATE",
                )?;
                let records: Records = serde_json::from_value(v).map_err(|_| "INVALID_INPUT")?;
                self.session = Some(Session::open(records, secret)?);
                json!({"state":"unlocked"})
            }
            "prepare" => {
                let id = self
                    .session
                    .as_mut()
                    .ok_or("INVALID_STATE")?
                    .prepare(now(&v)?)?;
                json!({"requestId":id})
            }
            "begin" => {
                self.session
                    .as_mut()
                    .ok_or("INVALID_STATE")?
                    .begin(text(&v, "requestId")?, now(&v)?)?;
                json!({"consumed":true})
            }
            "finish" => {
                self.session
                    .as_mut()
                    .ok_or("INVALID_STATE")?
                    .finish(secret, now(&v)?)?;
                json!({"probeVerified":true})
            }
            "cancel" => {
                self.registration = None;
                if let Some(s) = &mut self.session {
                    s.cancel();
                }
                json!({"cancelled":true})
            }
            "lock" => {
                self.registration = None;
                self.session = None;
                json!({"state":"locked"})
            }
            "status" => {
                json!({"state":match &self.session{Some(s) if s.pending.is_some()=>"prepared",Some(_)=>"unlocked",None=>"locked"}})
            }
            _ => return Err("INVALID_INPUT"),
        };
        serde_json::to_string(&result).map_err(|_| "INTERNAL_ERROR")
    }
    fn registration_key(&self, purpose: i32) -> R<Zeroizing<[u8; 32]>> {
        let r = self.registration.as_ref().ok_or("INVALID_STATE")?;
        match purpose {
            1 => Ok(r.profile_key.clone()),
            2 => Ok(r.signing_key.clone()),
            _ => Err("INVALID_INPUT"),
        }
    }
}
static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

mod bridge;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_separation_replay_and_cancel() {
        let reg = Registration::new("test").unwrap();
        assert!(Session::open(reg.records.clone(), reg.signing_key.as_ref()).is_err());
        let mut s = Session::open(reg.records.clone(), reg.profile_key.as_ref()).unwrap();
        let id = s.prepare(10).unwrap();
        assert!(s.prepare(11).is_err());
        s.begin(&id, 12).unwrap();
        assert!(s.begin(&id, 13).is_err());
        s.finish(reg.signing_key.as_ref(), 14).unwrap();
        assert!(s.finish(reg.signing_key.as_ref(), 15).is_err());
        let id = s.prepare(20).unwrap();
        s.begin(&id, 21).unwrap();
        s.cancel();
        assert!(s.finish(reg.signing_key.as_ref(), 22).is_err());
    }
    #[test]
    fn expiry_and_wrong_keys_consume_requests() {
        let reg = Registration::new("test").unwrap();
        let mut s = Session::open(reg.records.clone(), reg.profile_key.as_ref()).unwrap();
        let id = s.prepare(0).unwrap();
        assert_eq!(s.begin(&id, 60000), Err("EXPIRED"));
        assert!(s.begin(&id, 1).is_err());
        let id = s.prepare(10).unwrap();
        s.begin(&id, 11).unwrap();
        assert!(s.finish(reg.profile_key.as_ref(), 12).is_err());
        assert!(s.finish(reg.signing_key.as_ref(), 13).is_err());
        let id = s.prepare(20).unwrap();
        s.begin(&id, 21).unwrap();
        assert_eq!(s.finish(reg.signing_key.as_ref(), 60020), Err("EXPIRED"));
    }
    #[test]
    fn rejects_modified_record_headers_and_tags() {
        let reg = Registration::new("test").unwrap();
        let original = bytes(&reg.records.profile_record, 4096).unwrap();
        for offset in 0..original.len() {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            let mut records = reg.records.clone();
            records.profile_record = hex(&changed);
            assert!(Session::open(records, reg.profile_key.as_ref()).is_err());
        }
        let mut records = reg.records.clone();
        records.label = "other".into();
        assert!(Session::open(records, reg.profile_key.as_ref()).is_err());
        for len in 0..original.len() {
            assert!(
                unseal(
                    &profile(&reg.records.id).unwrap(),
                    1,
                    reg.profile_key.as_ref(),
                    &original[..len],
                    "test"
                )
                .is_err()
            );
        }
        let mut extra = original;
        extra.push(0);
        assert!(validate_record(&profile(&reg.records.id).unwrap(), 1, &extra).is_err());
    }
    #[test]
    fn validates_hex_and_command_lifecycle() {
        assert!(profile(&"A1".repeat(16)).is_err());
        assert!(profile("abc").is_err());
        let mut state = State::default();
        state.command("start", r#"{"label":"test"}"#, &[]).unwrap();
        assert!(state.registration_key(3).is_err());
        assert!(state.command("start", r#"{"label":"test"}"#, &[]).is_err());
        state.command("lock", "{}", &[]).unwrap();
        assert!(state.registration_key(1).is_err());
        assert_eq!(
            state.command("status", "{}", &[]).unwrap(),
            r#"{"state":"locked"}"#
        );
    }
}
