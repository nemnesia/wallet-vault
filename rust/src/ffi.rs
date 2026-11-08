//! C inputs are borrowed only for the duration of each call. Invalid non-null
//! pointers remain a caller contract violation; lengths/nulls are checked here.
#![allow(unsafe_op_in_unsafe_fn)]
use crate::{abi as a, *};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{Mutex, OnceLock},
};

static VAULTS: OnceLock<Mutex<BTreeMap<u64, Vault>>> = OnceLock::new();
fn registry() -> &'static Mutex<BTreeMap<u64, Vault>> {
    VAULTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn owner(id: u64) -> Result<Vault> {
    registry()
        .lock()
        .map_err(|_| Error::InternalFailure)?
        .get(&id)
        .cloned()
        .ok_or(Error::InvalidHandle)
}
fn boundary(f: impl FnOnce() -> Result<()>) -> u32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => e as u32,
        Err(_) => Error::InternalFailure as u32,
    }
}
unsafe fn array<'a, T>(p: *const T, n: u32, max: usize) -> Result<&'a [T]> {
    let n = n as usize;
    if n > max
        || (n > 0 && p.is_null())
        || n.checked_mul(std::mem::size_of::<T>())
            .is_none_or(|v| v > isize::MAX as usize)
    {
        return Err(Error::InvalidInput);
    }
    if n == 0 {
        Ok(&[])
    } else {
        Ok(std::slice::from_raw_parts(p, n))
    }
}
struct Decoder<'a> {
    vault: &'a Vault,
    _base: crate::budget::Reservation,
    memory: Vec<crate::budget::Reservation>,
}
impl<'a> Decoder<'a> {
    fn new(vault: &'a Vault) -> Result<Self> {
        Ok(Self {
            vault,
            _base: vault.ffi_reserve(2 * 1024 * 1024)?,
            memory: Vec::new(),
        })
    }
    unsafe fn bytes(&mut self, b: a::Bytes, min: usize, max: usize) -> Result<Vec<u8>> {
        let raw = array(b.ptr, b.len, max)?;
        format::sized(raw, min, max)?;
        self.memory.push(self.vault.ffi_reserve(raw.len() + 64)?);
        Ok(raw.to_vec())
    }
    unsafe fn data(&mut self, b: a::Bytes) -> Result<Vec<u8>> {
        format::data(array(b.ptr, b.len, format::MAX_PLAINTEXT + 4096)?)?;
        self.bytes(b, 0, format::MAX_PLAINTEXT + 4096)
    }
    unsafe fn wrap(&mut self, b: a::Bytes) -> Result<Vec<u8>> {
        format::wrap(array(b.ptr, b.len, 4096)?)?;
        self.bytes(b, 0, 4096)
    }
    unsafe fn context(&mut self, c: a::Context) -> Result<Context> {
        Ok(Context {
            target: self.bytes(c.target_id, 1, 255)?,
            purpose: self.bytes(c.purpose_id, 1, 255)?,
            generation: c.generation,
        })
    }
    unsafe fn source(&mut self, s: a::Source) -> Result<Source> {
        format::visit_snapshot(
            array(s.snapshot.ptr, s.snapshot.len, format::MAX_SNAPSHOT)?,
            |_, _, _| Ok(()),
        )?;
        let snapshot = self.bytes(s.snapshot, 0, format::MAX_SNAPSHOT)?;
        let target = self.bytes(s.expected.target_id, 1, 255)?;
        let purposes = array(s.expected.purposes, s.expected.purpose_count, 32)?
            .iter()
            .map(|p| {
                Ok(Expectation {
                    purpose: self.bytes(p.purpose_id, 1, 255)?,
                    generation: p.generation,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Source {
            snapshot,
            expected: ExpectedSnapshot { target, purposes },
        })
    }
    unsafe fn plan(&mut self, p: a::PurposePlan) -> Result<PurposePlan> {
        let purpose = self.bytes(p.purpose_id, 1, 255)?;
        let routes = array(p.routes, p.route_count, 15)?
            .iter()
            .map(|r| {
                Ok(RoutePlan {
                    action: r.action,
                    kind: r.kind,
                    source_route_id: self.bytes(r.source_route_id, 0, 16)?,
                    credential_id: self.bytes(r.credential_id, 0, 1024)?,
                    protection: r.protection,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PurposePlan { purpose, routes })
    }
    unsafe fn purpose(&mut self, p: a::PurposeInput) -> Result<PurposeInput> {
        Ok(PurposeInput {
            plan: self.plan(p.plan)?,
            plaintext: Secret(self.bytes(p.plaintext, 0, format::MAX_PLAINTEXT)?),
        })
    }
    unsafe fn plans(&mut self, p: a::PurposePlanArray) -> Result<Vec<PurposePlan>> {
        array(p.items, p.count, 32)?
            .iter()
            .map(|p| self.plan(*p))
            .collect()
    }
    unsafe fn routes(&mut self, p: a::UnlockRouteArray) -> Result<Vec<UnlockRoute>> {
        array(p.items, p.count, 32)?
            .iter()
            .map(|r| {
                Ok(UnlockRoute {
                    purpose: self.bytes(r.purpose_id, 1, 255)?,
                    route: self.bytes(r.route_id, 16, 16)?,
                })
            })
            .collect()
    }
    unsafe fn request(&mut self, r: &a::VaultRequest) -> Result<Request> {
        let p = r.payload;
        Ok(match r.tag {
            1 => {
                let p = p.create;
                Request::Create {
                    target: self.bytes(p.target_id, 1, 255)?,
                    purposes: array(p.purposes.items, p.purposes.count, 32)?
                        .iter()
                        .map(|p| self.purpose(*p))
                        .collect::<Result<_>>()?,
                }
            }
            2 => {
                let p = p.addpurpose;
                Request::AddPurpose {
                    source: self.source(p.source)?,
                    purpose: self.purpose(p.purpose)?,
                }
            }
            3 => {
                let p = p.removepurpose;
                Request::RemovePurpose {
                    source: self.source(p.source)?,
                    purposes: array(p.purpose_ids.items, p.purpose_ids.count, 32)?
                        .iter()
                        .map(|p| self.bytes(*p, 1, 255))
                        .collect::<Result<_>>()?,
                }
            }
            4 => {
                let p = p.unlock;
                Request::Unlock {
                    context: self.context(p.context)?,
                    data: self.data(p.data)?,
                    wrap: self.wrap(p.wrap)?,
                    lifetime: lifetime(p.lifetime)?,
                }
            }
            5 => {
                let p = p.decrypt;
                Request::Decrypt {
                    handle: p.context_handle,
                    context: self.context(p.context)?,
                    data: self.data(p.data)?,
                }
            }
            6 => {
                let p = p.replacedata;
                Request::ReplaceData {
                    source: self.source(p.source)?,
                    handle: p.context_handle,
                    purpose: self.bytes(p.purpose_id, 1, 255)?,
                    plaintext: Secret(self.bytes(p.plaintext, 0, format::MAX_PLAINTEXT)?),
                }
            }
            7 => {
                let p = p.rewrap;
                Request::Rewrap {
                    source: self.source(p.source)?,
                    plans: self.plans(p.plans)?,
                    fresh_unlock_routes: self.routes(p.fresh_unlock_routes)?,
                }
            }
            8 => {
                let p = p.rotatedek;
                Request::RotateDek {
                    source: self.source(p.source)?,
                    plans: self.plans(p.plans)?,
                    fresh_unlock_routes: self.routes(p.fresh_unlock_routes)?,
                }
            }
            9 => {
                let p = p.recover;
                Request::Recover {
                    source: self.source(p.source)?,
                    plans: self.plans(p.plans)?,
                }
            }
            10 => {
                let p = p.reissuerecovery;
                Request::ReissueRecovery {
                    source: self.source(p.source)?,
                    fresh_unlock_routes: self.routes(p.fresh_unlock_routes)?,
                }
            }
            11 => {
                let p = p.recoverselected;
                Request::RecoverSelected {
                    selection: array(p.selection.items, p.selection.count, 32)?
                        .iter()
                        .map(|i| {
                            Ok(SelectionInput {
                                context: self.context(i.context)?,
                                data: self.data(i.data)?,
                                recovery_wrap: self.wrap(i.recovery_wrap)?,
                            })
                        })
                        .collect::<Result<_>>()?,
                    lifetime: lifetime(p.lifetime)?,
                }
            }
            _ => return Err(Error::InvalidInput),
        })
    }
    unsafe fn response(&mut self, r: &a::VaultAdapterResponse) -> Result<AdapterResponse> {
        if !(1..=9).contains(&r.kind) {
            return Err(Error::InvalidInput);
        }
        if r.status != 0 {
            return Ok(AdapterResponse::Failure {
                kind: r.kind,
                error: error(r.status)?,
            });
        }
        let p = r.payload;
        Ok(match r.kind {
            1 => AdapterResponse::Password(Secret(self.bytes(p.password.password, 1, 1024)?)),
            2 => AdapterResponse::Recovery(Secret(self.bytes(p.recovery.recovery_key, 32, 32)?)),
            3 => AdapterResponse::Prf(Secret(self.bytes(p.prf.prf_output, 32, 32)?)),
            4 => {
                let p = p.androidprepare;
                AdapterResponse::AndroidPrepared {
                    key_ref: self.bytes(p.key_ref, 1, 1024)?,
                    protection: p.actual_protection,
                    nonce: self.bytes(p.nonce, 12, 12)?,
                }
            }
            5 => AdapterResponse::AndroidEncrypted(self.bytes(
                p.androidencrypt.ciphertext_and_tag,
                48,
                48,
            )?),
            6 => AdapterResponse::AndroidDecrypted(Secret(self.bytes(
                p.androiddecrypt.dek,
                32,
                32,
            )?)),
            7 => {
                let p = p.iosprepare;
                AdapterResponse::IosPrepared {
                    key_ref: self.bytes(p.key_ref, 1, 1024)?,
                    ephemeral_public_key: self.bytes(p.ephemeral_public_key, 65, 65)?,
                }
            }
            8 => AdapterResponse::IosEncrypted(self.bytes(
                p.iosencrypt.ciphertext_and_tag,
                48,
                48,
            )?),
            9 => AdapterResponse::IosDecrypted(Secret(self.bytes(p.iosdecrypt.dek, 32, 32)?)),
            _ => return Err(Error::InvalidInput),
        })
    }
}
fn lifetime(v: u32) -> Result<Lifetime> {
    match v {
        1 => Ok(Lifetime::Operation),
        2 => Ok(Lifetime::Explicit),
        _ => Err(Error::InvalidInput),
    }
}
fn error(v: u32) -> Result<Error> {
    Ok(match v {
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
        _ => return Err(Error::InvalidInput),
    })
}
fn bytes(v: &[u8]) -> a::Bytes {
    a::Bytes {
        ptr: if v.is_empty() {
            ptr::null()
        } else {
            v.as_ptr()
        },
        len: v.len() as u32,
    }
}
fn context(c: &Context) -> a::Context {
    a::Context {
        target_id: bytes(&c.target),
        purpose_id: bytes(&c.purpose),
        generation: c.generation,
    }
}
#[repr(C)]
struct OwnedStep {
    repr: a::VaultStep,
    core: Step,
    requests: Vec<a::VaultAdapterRequest>,
    expected: Vec<a::PurposeExpectation>,
    recovered: Vec<a::SelectionResultItem>,
    _memory: crate::budget::Reservation,
}
fn exported(step: Step, memory: crate::budget::Reservation) -> Result<*mut a::VaultStep> {
    let mut owned = Box::new(OwnedStep {
        repr: a::VaultStep {
            tag: 0,
            payload: a::VaultStepPayload {
                completed: a::VaultCompleted {
                    request_tag: 0,
                    payload: a::VaultCompletedPayload {
                        unlock: a::UnlockResult { context_handle: 0 },
                    },
                },
            },
        },
        core: step,
        requests: Vec::new(),
        expected: Vec::new(),
        recovered: Vec::new(),
        _memory: memory,
    });
    match &owned.core.value {
        StepValue::Pending {
            operation_id,
            requests,
        } => {
            for r in requests {
                let payload = match &r.payload {
                    AdapterPayload::Password {
                        context: c,
                        route,
                        for_protection,
                    } => a::VaultAdapterRequestPayload {
                        password: a::PasswordAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            for_protection: u32::from(*for_protection),
                        },
                    },
                    AdapterPayload::Recovery { expected } => {
                        owned.expected.extend(expected.purposes.iter().map(|p| {
                            a::PurposeExpectation {
                                purpose_id: bytes(&p.purpose),
                                generation: p.generation,
                            }
                        }));
                        a::VaultAdapterRequestPayload {
                            recovery: a::RecoveryAdapterRequest {
                                expected: a::ExpectedSnapshot {
                                    target_id: bytes(&expected.target),
                                    purposes: owned.expected.as_ptr(),
                                    purpose_count: owned.expected.len() as u32,
                                },
                            },
                        }
                    }
                    AdapterPayload::Prf {
                        context: c,
                        route,
                        credential_id,
                        input,
                    } => a::VaultAdapterRequestPayload {
                        prf: a::PrfAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            credential_id: bytes(credential_id),
                            prf_input: bytes(input),
                        },
                    },
                    AdapterPayload::AndroidPrepare {
                        context: c,
                        route,
                        protection,
                    } => a::VaultAdapterRequestPayload {
                        androidprepare: a::AndroidPrepareAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            protection: *protection,
                        },
                    },
                    AdapterPayload::AndroidEncrypt {
                        context: c,
                        route,
                        key_ref,
                        salt,
                        nonce,
                        aad,
                        dek,
                    } => a::VaultAdapterRequestPayload {
                        androidencrypt: a::AndroidEncryptAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            key_ref: bytes(key_ref),
                            salt: bytes(salt),
                            nonce: bytes(nonce),
                            aad: bytes(aad),
                            dek: bytes(&dek.0),
                        },
                    },
                    AdapterPayload::AndroidDecrypt {
                        context: c,
                        route,
                        key_ref,
                        salt,
                        nonce,
                        aad,
                        ciphertext,
                    } => a::VaultAdapterRequestPayload {
                        androiddecrypt: a::AndroidDecryptAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            key_ref: bytes(key_ref),
                            salt: bytes(salt),
                            nonce: bytes(nonce),
                            aad: bytes(aad),
                            ciphertext_and_tag: bytes(ciphertext),
                        },
                    },
                    AdapterPayload::IosPrepare { context: c, route } => {
                        a::VaultAdapterRequestPayload {
                            iosprepare: a::IosPrepareAdapterRequest {
                                context: context(c),
                                route_id: bytes(route),
                            },
                        }
                    }
                    AdapterPayload::IosEncrypt {
                        context: c,
                        route,
                        key_ref,
                        salt,
                        nonce,
                        info,
                        aad,
                        dek,
                    } => a::VaultAdapterRequestPayload {
                        iosencrypt: a::IosEncryptAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            key_ref: bytes(key_ref),
                            salt: bytes(salt),
                            nonce: bytes(nonce),
                            info: bytes(info),
                            aad: bytes(aad),
                            dek: bytes(&dek.0),
                        },
                    },
                    AdapterPayload::IosDecrypt {
                        context: c,
                        route,
                        key_ref,
                        ephemeral_public_key,
                        salt,
                        nonce,
                        info,
                        aad,
                        ciphertext,
                    } => a::VaultAdapterRequestPayload {
                        iosdecrypt: a::IosDecryptAdapterRequest {
                            context: context(c),
                            route_id: bytes(route),
                            key_ref: bytes(key_ref),
                            ephemeral_public_key: bytes(ephemeral_public_key),
                            salt: bytes(salt),
                            nonce: bytes(nonce),
                            info: bytes(info),
                            aad: bytes(aad),
                            ciphertext_and_tag: bytes(ciphertext),
                        },
                    },
                };
                owned.requests.push(a::VaultAdapterRequest {
                    kind: r.payload.kind(),
                    operation_id: r.operation_id,
                    request_id: r.request_id,
                    payload,
                });
            }
            owned.repr = a::VaultStep {
                tag: 2,
                payload: a::VaultStepPayload {
                    pending: a::VaultPending {
                        operation_id: *operation_id,
                        requests: a::VaultAdapterRequestArray {
                            items: owned.requests.as_ptr(),
                            count: owned.requests.len() as u32,
                        },
                    },
                },
            };
        }
        StepValue::Completed {
            request_tag,
            result,
        } => {
            let payload = match result {
                Completed::Unlock { handle } => a::VaultCompletedPayload {
                    unlock: a::UnlockResult {
                        context_handle: *handle,
                    },
                },
                Completed::Decrypt { plaintext } => a::VaultCompletedPayload {
                    decrypt: a::DecryptResult {
                        plaintext: bytes(&plaintext.0),
                    },
                },
                Completed::RecoveredSelected { target, recovered } => {
                    owned
                        .recovered
                        .extend(recovered.iter().map(|(c, h)| a::SelectionResultItem {
                            context: context(c),
                            context_handle: *h,
                        }));
                    a::VaultCompletedPayload {
                        recoverselected: a::RecoverSelectedResult {
                            target_id: bytes(target),
                            recovered: a::SelectionResultItemArray {
                                items: owned.recovered.as_ptr(),
                                count: owned.recovered.len() as u32,
                            },
                        },
                    }
                }
                Completed::Candidate(c) => {
                    let common = a::CandidateResult {
                        candidate_id: c.id,
                        snapshot: bytes(&c.snapshot),
                        has_base: u32::from(c.base_hash.is_some()),
                        base_hash: c.base_hash.as_ref().map_or(bytes(&[]), |h| bytes(h)),
                        new_hash: bytes(&c.new_hash),
                    };
                    if let Some(key) = &c.recovery_key {
                        let value = a::RecoveryCandidateResult {
                            candidate_id: common.candidate_id,
                            snapshot: common.snapshot,
                            has_base: common.has_base,
                            base_hash: common.base_hash,
                            new_hash: common.new_hash,
                            recovery_key: bytes(&key.0),
                        };
                        if *request_tag == 1 {
                            a::VaultCompletedPayload { create: value }
                        } else {
                            a::VaultCompletedPayload {
                                reissuerecovery: value,
                            }
                        }
                    } else {
                        match *request_tag {
                            2 => a::VaultCompletedPayload { addpurpose: common },
                            3 => a::VaultCompletedPayload {
                                removepurpose: common,
                            },
                            6 => a::VaultCompletedPayload {
                                replacedata: common,
                            },
                            7 => a::VaultCompletedPayload { rewrap: common },
                            8 => a::VaultCompletedPayload { rotatedek: common },
                            9 => a::VaultCompletedPayload { recover: common },
                            _ => return Err(Error::InternalFailure),
                        }
                    }
                }
            };
            owned.repr = a::VaultStep {
                tag: 1,
                payload: a::VaultStepPayload {
                    completed: a::VaultCompleted {
                        request_tag: *request_tag,
                        payload,
                    },
                },
            };
        }
    }
    Ok(Box::into_raw(owned).cast())
}
/// # Safety
/// Options and output must be valid for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_create(options: *const a::VaultOptions, out: *mut u64) -> u32 {
    boundary(|| {
        if out.is_null() {
            return Err(Error::InvalidInput);
        }
        *out = 0;
        if options.is_null() {
            return Err(Error::InvalidInput);
        }
        let v = Vault::new((*options).memory_budget_bytes)?;
        let id = crate::engine::next()?;
        registry()
            .lock()
            .map_err(|_| Error::InternalFailure)?
            .insert(id, v);
        *out = id;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn vault_destroy(v: u64) -> u32 {
    boundary(|| {
        let owner = registry()
            .lock()
            .map_err(|_| Error::InternalFailure)?
            .remove(&v)
            .ok_or(Error::InvalidHandle)?;
        owner.destroy()
    })
}
/// # Safety
/// Request and output pointers must be valid; all nested inputs are borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_begin(
    v: u64,
    request: *const a::VaultRequest,
    out: *mut *mut a::VaultStep,
) -> u32 {
    boundary(|| {
        if out.is_null() {
            return Err(Error::InvalidInput);
        }
        *out = ptr::null_mut();
        if request.is_null() {
            return Err(Error::InvalidInput);
        }
        let v = owner(v)?;
        let mut decoder = Decoder::new(&v)?;
        let request = decoder.request(&*request)?;
        let output_memory = v.ffi_reserve(128 * 1024)?;
        let step = v.begin(&request)?;
        *out = exported(step, output_memory)?;
        Ok(())
    })
}
/// # Safety
/// Response and output pointers must be valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_resume(
    v: u64,
    op: u64,
    rid: u64,
    response: *const a::VaultAdapterResponse,
    out: *mut *mut a::VaultStep,
) -> u32 {
    boundary(|| {
        if out.is_null() {
            return Err(Error::InvalidInput);
        }
        *out = ptr::null_mut();
        let v = owner(v)?;
        // Reference validity is checked before decoding, so a malformed response for
        // another request cannot terminate the legitimate pending operation.
        v.check_waiting(op, rid)?;
        let mut decoder = match Decoder::new(&v) {
            Ok(d) => d,
            Err(e) => {
                v.cancel(op)?;
                return Err(e);
            }
        };
        let decoded = if response.is_null() {
            Err(Error::InvalidInput)
        } else {
            decoder.response(&*response)
        };
        let response = match decoded {
            Ok(r) => r,
            Err(e) => {
                v.cancel(op)?;
                return Err(e);
            }
        };
        let output_memory = match v.ffi_reserve(128 * 1024) {
            Ok(m) => m,
            Err(e) => {
                v.cancel(op)?;
                return Err(e);
            }
        };
        let step = v.resume(op, rid, &response)?;
        *out = exported(step, output_memory)?;
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn vault_cancel(v: u64, op: u64) -> u32 {
    boundary(|| owner(v)?.cancel(op))
}
#[unsafe(no_mangle)]
pub extern "C" fn vault_release_context(v: u64, h: u64) -> u32 {
    boundary(|| owner(v)?.release_context(h))
}
#[unsafe(no_mangle)]
pub extern "C" fn vault_discard_candidate(v: u64, h: u64) -> u32 {
    boundary(|| owner(v)?.discard_candidate(h))
}
/// # Safety
/// The hash pointer must reference new_hash_len readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_confirm_saved(v: u64, id: u64, hash: *const u8, n: u32) -> u32 {
    boundary(|| {
        if n != 32 {
            return Err(Error::InvalidInput);
        }
        owner(v)?.confirm_saved(id, array(hash, n, 32)?)
    })
}
/// # Safety
/// Step must be an unmodified, not-yet-freed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vault_free_step(step: *mut a::VaultStep) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !step.is_null() {
            drop(Box::from_raw(step.cast::<OwnedStep>()));
        }
    }));
}
