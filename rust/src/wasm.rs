//! WASM boundary: Uint8Array bytes, bigint uint64s, numeric tags, Promise methods.
use crate::*;
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, prelude::*};

type JResult<T> = std::result::Result<T, JsValue>;
fn err(e: Error) -> JsValue {
    JsValue::from(e as u32)
}
fn field(o: &JsValue, name: &str) -> JResult<JsValue> {
    Reflect::get(o, &JsValue::from(name)).map_err(|_| err(Error::InvalidInput))
}
fn u32_value(v: JsValue) -> JResult<u32> {
    let n = v.as_f64().ok_or_else(|| err(Error::InvalidInput))?;
    if !n.is_finite() || n < 0. || n > u32::MAX as f64 || n.fract() != 0. {
        return Err(err(Error::InvalidInput));
    }
    Ok(n as u32)
}
fn uint(o: &JsValue, n: &str) -> JResult<u32> {
    u32_value(field(o, n)?)
}
fn u64_value(v: JsValue) -> JResult<u64> {
    if !v.is_bigint() {
        return Err(err(Error::InvalidInput));
    }
    BigInt::from(v)
        .to_string(10)
        .map_err(|_| err(Error::InvalidInput))?
        .as_string()
        .ok_or_else(|| err(Error::InvalidInput))?
        .parse()
        .map_err(|_| err(Error::InvalidInput))
}
fn wide(o: &JsValue, n: &str) -> JResult<u64> {
    u64_value(field(o, n)?)
}
fn array(o: &JsValue, n: &str, max: u32) -> JResult<Array> {
    let value = field(o, n)?;
    if !Array::is_array(&value) {
        return Err(err(Error::InvalidInput));
    }
    let a = Array::from(&value);
    if a.length() > max {
        return Err(err(Error::InvalidInput));
    }
    Ok(a)
}
fn lifetime(o: &JsValue) -> JResult<Lifetime> {
    match uint(o, "lifetime")? {
        1 => Ok(Lifetime::Operation),
        2 => Ok(Lifetime::Explicit),
        _ => Err(err(Error::InvalidInput)),
    }
}
struct Decoder<'a> {
    vault: &'a Vault,
    _base: crate::budget::Reservation,
    memory: Vec<crate::budget::Reservation>,
}
impl<'a> Decoder<'a> {
    fn new(vault: &'a Vault) -> JResult<Self> {
        Ok(Self {
            vault,
            _base: vault.ffi_reserve(2 * 1024 * 1024).map_err(err)?,
            memory: Vec::new(),
        })
    }
    fn bytes(&mut self, o: &JsValue, n: &str, min: usize, max: usize) -> JResult<Vec<u8>> {
        let value = field(o, n)?;
        let a = value
            .dyn_ref::<Uint8Array>()
            .ok_or_else(|| err(Error::InvalidInput))?;
        let len = a.length() as usize;
        if len < min || len > max {
            return Err(err(Error::InvalidInput));
        }
        self.memory
            .push(self.vault.ffi_reserve(len + 64).map_err(err)?);
        Ok(a.to_vec())
    }
    fn context(&mut self, o: &JsValue) -> JResult<Context> {
        Ok(Context {
            target: self.bytes(o, "target_id", 1, 255)?,
            purpose: self.bytes(o, "purpose_id", 1, 255)?,
            generation: wide(o, "generation")?,
        })
    }
    fn source(&mut self, o: &JsValue) -> JResult<Source> {
        let snapshot = self.bytes(o, "snapshot", 0, format::MAX_SNAPSHOT)?;
        let e = field(o, "expected")?;
        let target = self.bytes(&e, "target_id", 1, 255)?;
        let mut purposes = Vec::new();
        for p in array(&e, "purposes", 32)?.iter() {
            purposes.push(Expectation {
                purpose: self.bytes(&p, "purpose_id", 1, 255)?,
                generation: wide(&p, "generation")?,
            });
        }
        Ok(Source {
            snapshot,
            expected: ExpectedSnapshot { target, purposes },
        })
    }
    fn plan(&mut self, o: &JsValue) -> JResult<PurposePlan> {
        let purpose = self.bytes(o, "purpose_id", 1, 255)?;
        let mut routes = Vec::new();
        for r in array(o, "routes", 15)?.iter() {
            routes.push(RoutePlan {
                action: uint(&r, "action")?,
                kind: uint(&r, "kind")?,
                source_route_id: self.bytes(&r, "source_route_id", 0, 16)?,
                credential_id: self.bytes(&r, "credential_id", 0, 1024)?,
                protection: uint(&r, "protection")?,
            });
        }
        Ok(PurposePlan { purpose, routes })
    }
    fn purpose(&mut self, o: &JsValue) -> JResult<PurposeInput> {
        Ok(PurposeInput {
            plan: self.plan(&field(o, "plan")?)?,
            plaintext: Secret(self.bytes(o, "plaintext", 0, format::MAX_PLAINTEXT)?),
        })
    }
    fn plans(&mut self, o: &JsValue) -> JResult<Vec<PurposePlan>> {
        array(o, "plans", 32)?
            .iter()
            .map(|p| self.plan(&p))
            .collect()
    }
    fn routes(&mut self, o: &JsValue) -> JResult<Vec<UnlockRoute>> {
        array(o, "fresh_unlock_routes", 32)?
            .iter()
            .map(|r| {
                Ok(UnlockRoute {
                    purpose: self.bytes(&r, "purpose_id", 1, 255)?,
                    route: self.bytes(&r, "route_id", 16, 16)?,
                })
            })
            .collect()
    }
    fn request(&mut self, o: &JsValue) -> JResult<Request> {
        let tag = uint(o, "tag")?;
        let p = field(o, "payload")?;
        Ok(match tag {
            1 => Request::Create {
                target: self.bytes(&p, "target_id", 1, 255)?,
                purposes: array(&p, "purposes", 32)?
                    .iter()
                    .map(|p| self.purpose(&p))
                    .collect::<JResult<_>>()?,
            },
            2 => Request::AddPurpose {
                source: self.source(&field(&p, "source")?)?,
                purpose: self.purpose(&field(&p, "purpose")?)?,
            },
            3 => Request::RemovePurpose {
                source: self.source(&field(&p, "source")?)?,
                purposes: array(&p, "purpose_ids", 32)?
                    .iter()
                    .map(|v| {
                        let wrapper = Object::new();
                        Reflect::set(&wrapper, &JsValue::from("value"), &v)
                            .map_err(|_| err(Error::InvalidInput))?;
                        self.bytes(&wrapper.into(), "value", 1, 255)
                    })
                    .collect::<JResult<_>>()?,
            },
            4 => Request::Unlock {
                context: self.context(&field(&p, "context")?)?,
                data: self.bytes(&p, "data", 0, format::MAX_PLAINTEXT + 4096)?,
                wrap: self.bytes(&p, "wrap", 0, 4096)?,
                lifetime: lifetime(&p)?,
            },
            5 => Request::Decrypt {
                handle: wide(&p, "context_handle")?,
                context: self.context(&field(&p, "context")?)?,
                data: self.bytes(&p, "data", 0, format::MAX_PLAINTEXT + 4096)?,
            },
            6 => Request::ReplaceData {
                source: self.source(&field(&p, "source")?)?,
                handle: wide(&p, "context_handle")?,
                purpose: self.bytes(&p, "purpose_id", 1, 255)?,
                plaintext: Secret(self.bytes(&p, "plaintext", 0, format::MAX_PLAINTEXT)?),
            },
            7 => Request::Rewrap {
                source: self.source(&field(&p, "source")?)?,
                plans: self.plans(&p)?,
                fresh_unlock_routes: self.routes(&p)?,
            },
            8 => Request::RotateDek {
                source: self.source(&field(&p, "source")?)?,
                plans: self.plans(&p)?,
                fresh_unlock_routes: self.routes(&p)?,
            },
            9 => Request::Recover {
                source: self.source(&field(&p, "source")?)?,
                plans: self.plans(&p)?,
            },
            10 => Request::ReissueRecovery {
                source: self.source(&field(&p, "source")?)?,
                fresh_unlock_routes: self.routes(&p)?,
            },
            11 => Request::RecoverSelected {
                selection: array(&p, "selection", 32)?
                    .iter()
                    .map(|i| {
                        Ok(SelectionInput {
                            context: self.context(&field(&i, "context")?)?,
                            data: self.bytes(&i, "data", 0, format::MAX_PLAINTEXT + 4096)?,
                            recovery_wrap: self.bytes(&i, "recovery_wrap", 0, 4096)?,
                        })
                    })
                    .collect::<JResult<_>>()?,
                lifetime: lifetime(&p)?,
            },
            _ => return Err(err(Error::InvalidInput)),
        })
    }
    fn response(&mut self, o: &JsValue) -> JResult<AdapterResponse> {
        let kind = uint(o, "kind")?;
        let status = uint(o, "status")?;
        if !(1..=3).contains(&kind) {
            return Err(err(Error::InvalidInput));
        }
        if status != 0 {
            return Ok(AdapterResponse::Failure {
                kind,
                error: match status {
                    1 => Error::InvalidInput,
                    2 => Error::Unsupported,
                    3 => Error::ContextMismatch,
                    4 => Error::VerificationFailed,
                    5 => Error::RandomFailure,
                    6 => Error::Cancelled,
                    7 => Error::KeyInvalidated,
                    8 => Error::InvalidHandle,
                    9 => Error::Busy,
                    10 => Error::InternalFailure,
                    11 => Error::ResourceLimit,
                    12 => Error::AuthenticationFailed,
                    13 => Error::AuthenticationLockedOut,
                    14 => Error::AdapterFailure,
                    _ => return Err(err(Error::InvalidInput)),
                },
            });
        }
        let p = field(o, "payload")?;
        Ok(match kind {
            1 => AdapterResponse::Password(Secret(self.bytes(&p, "password", 1, 1024)?)),
            2 => AdapterResponse::Recovery(Secret(self.bytes(&p, "recovery_key", 32, 32)?)),
            3 => AdapterResponse::Prf(Secret(self.bytes(&p, "prf_output", 32, 32)?)),
            _ => return Err(err(Error::InvalidInput)),
        })
    }
}
fn object() -> JsValue {
    Object::new().into()
}
fn set(o: &JsValue, n: &str, v: impl Into<JsValue>) -> JResult<()> {
    Reflect::set(o, &JsValue::from(n), &v.into()).map_err(|_| err(Error::InternalFailure))?;
    Ok(())
}
fn bigint(v: u64) -> JsValue {
    BigInt::from(v).into()
}
fn bytes(v: &[u8]) -> JsValue {
    Uint8Array::from(v).into()
}
fn context(c: &Context) -> JResult<JsValue> {
    let o = object();
    set(&o, "target_id", bytes(&c.target))?;
    set(&o, "purpose_id", bytes(&c.purpose))?;
    set(&o, "generation", bigint(c.generation))?;
    Ok(o)
}
fn result(step: &Step) -> JResult<JsValue> {
    let o = object();
    let payload = object();
    set(&o, "payload", payload.clone())?;
    match step.value() {
        StepValue::Pending {
            operation_id,
            requests,
        } => {
            set(&o, "tag", 2)?;
            set(&payload, "operation_id", bigint(*operation_id))?;
            let array = Array::new();
            for r in requests {
                let request = object();
                let p = object();
                set(&request, "kind", r.payload.kind())?;
                set(&request, "operation_id", bigint(r.operation_id))?;
                set(&request, "request_id", bigint(r.request_id))?;
                set(&request, "payload", p.clone())?;
                match &r.payload {
                    AdapterPayload::Password {
                        context: c,
                        route,
                        for_protection,
                    } => {
                        set(&p, "context", context(c)?)?;
                        set(&p, "route_id", bytes(route))?;
                        set(&p, "for_protection", u32::from(*for_protection))?;
                    }
                    AdapterPayload::Recovery { expected } => {
                        let e = object();
                        set(&e, "target_id", bytes(&expected.target))?;
                        let ps = Array::new();
                        for p in &expected.purposes {
                            let item = object();
                            set(&item, "purpose_id", bytes(&p.purpose))?;
                            set(&item, "generation", bigint(p.generation))?;
                            ps.push(&item);
                        }
                        set(&e, "purposes", ps)?;
                        set(&p, "expected", e)?;
                    }
                    AdapterPayload::Prf {
                        context: c,
                        route,
                        credential_id,
                        input,
                    } => {
                        set(&p, "context", context(c)?)?;
                        set(&p, "route_id", bytes(route))?;
                        set(&p, "credential_id", bytes(credential_id))?;
                        set(&p, "prf_input", bytes(input))?;
                    }
                    _ => return Err(err(Error::Unsupported)),
                }
                array.push(&request);
            }
            set(&payload, "requests", array)?;
        }
        StepValue::Completed {
            request_tag,
            result,
        } => {
            set(&o, "tag", 1)?;
            set(&payload, "request_tag", *request_tag)?;
            let p = object();
            set(&payload, "payload", p.clone())?;
            match result {
                Completed::Unlock { handle } => set(&p, "context_handle", bigint(*handle))?,
                Completed::Decrypt { plaintext } => set(&p, "plaintext", bytes(&plaintext.0))?,
                Completed::Candidate(c) => {
                    set(&p, "candidate_id", bigint(c.id))?;
                    set(&p, "snapshot", bytes(&c.snapshot))?;
                    set(&p, "has_base", u32::from(c.base_hash.is_some()))?;
                    set(
                        &p,
                        "base_hash",
                        bytes(c.base_hash.as_ref().map_or(&[][..], |h| h.as_slice())),
                    )?;
                    set(&p, "new_hash", bytes(&c.new_hash))?;
                    if let Some(k) = &c.recovery_key {
                        set(&p, "recovery_key", bytes(&k.0))?;
                    }
                }
                Completed::RecoveredSelected { target, recovered } => {
                    set(&p, "target_id", bytes(target))?;
                    let a = Array::new();
                    for (c, h) in recovered {
                        let item = object();
                        set(&item, "context", context(c)?)?;
                        set(&item, "context_handle", bigint(*h))?;
                        a.push(&item);
                    }
                    set(&p, "recovered", a)?;
                }
            }
        }
    }
    Ok(o)
}
#[wasm_bindgen]
pub struct WasmVault {
    core: Vault,
}
#[wasm_bindgen]
impl WasmVault {
    #[wasm_bindgen(constructor)]
    pub fn new(memory_budget_bytes: JsValue) -> JResult<WasmVault> {
        Ok(Self {
            core: Vault::new(u64_value(memory_budget_bytes)?).map_err(err)?,
        })
    }
    pub async fn begin(&self, request: JsValue) -> JResult<JsValue> {
        let mut d = Decoder::new(&self.core)?;
        let r = d.request(&request)?;
        let step = self.core.begin(&r).map_err(err)?;
        result(&step)
    }
    pub async fn resume(
        &self,
        operation_id: JsValue,
        request_id: JsValue,
        response: JsValue,
    ) -> JResult<JsValue> {
        let op = u64_value(operation_id)?;
        let rid = u64_value(request_id)?;
        self.core.check_waiting(op, rid).map_err(err)?;
        let mut decoder = match Decoder::new(&self.core) {
            Ok(d) => d,
            Err(e) => {
                self.core.cancel(op).map_err(err)?;
                return Err(e);
            }
        };
        let decoded = decoder.response(&response);
        let r = match decoded {
            Ok(r) => r,
            Err(e) => {
                self.core.cancel(op).map_err(err)?;
                return Err(e);
            }
        };
        let step = self.core.resume(op, rid, &r).map_err(err)?;
        result(&step)
    }
    pub async fn cancel(&self, operation_id: JsValue) -> JResult<()> {
        self.core.cancel(u64_value(operation_id)?).map_err(err)
    }
    pub async fn release_context(&self, handle: JsValue) -> JResult<()> {
        self.core.release_context(u64_value(handle)?).map_err(err)
    }
    pub async fn discard_candidate(&self, id: JsValue) -> JResult<()> {
        self.core.discard_candidate(u64_value(id)?).map_err(err)
    }
    pub async fn confirm_saved(&self, id: JsValue, hash: JsValue) -> JResult<()> {
        let hash = hash
            .dyn_ref::<Uint8Array>()
            .ok_or_else(|| err(Error::InvalidInput))?;
        if hash.length() != 32 {
            return Err(err(Error::InvalidInput));
        }
        self.core
            .confirm_saved(u64_value(id)?, &hash.to_vec())
            .map_err(err)
    }
    pub async fn destroy(&self) -> JResult<()> {
        self.core.destroy().map_err(err)
    }
}
