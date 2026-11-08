use crate::{
    budget::{Budget, Reservation, Slot},
    crypto,
    model::Key,
    operation::{self, Draft, Halt},
    *,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

static NEXT: AtomicU64 = AtomicU64::new(1);
pub(crate) fn next() -> Result<u64> {
    NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
        .map_err(|_| Error::ResourceLimit)
}
struct KeyContext {
    context: Context,
    key: Key,
    lifetime: Lifetime,
    busy: Option<u64>,
    _slot: Slot,
    _memory: Reservation,
}
struct SavedCandidate {
    target: Vec<u8>,
    hash: [u8; 32],
    invalidated: Vec<Vec<u8>>,
    _slot: Slot,
    _memory: Reservation,
}
struct Operation {
    request: Request,
    responses: Vec<AdapterResponse>,
    tape: Secret,
    cache: Vec<(usize, Key)>,
    waiting: Option<(u64, u32)>,
    key: Option<Key>,
    bound: Option<u64>,
    reserved_contexts: Vec<(Slot, Reservation)>,
    _memory: Reservation,
    _slot: Slot,
}
#[derive(Clone)]
struct Entry {
    operation: Arc<Mutex<Operation>>,
    cancelled: Arc<AtomicBool>,
}
struct State {
    live: bool,
    operations: BTreeMap<u64, Entry>,
    contexts: BTreeMap<u64, KeyContext>,
    candidates: BTreeMap<u64, SavedCandidate>,
}
/// Thread-safe owner. Clones refer to the same environment, never to copied key state.
#[derive(Clone)]
pub struct Vault {
    state: Arc<Mutex<State>>,
    budget: Arc<Budget>,
    _memory: Arc<Reservation>,
}
impl Vault {
    pub fn new(memory_budget_bytes: u64) -> Result<Self> {
        let budget = Budget::shared(memory_budget_bytes)?;
        let memory = budget.reserve(8192)?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                live: true,
                operations: BTreeMap::new(),
                contexts: BTreeMap::new(),
                candidates: BTreeMap::new(),
            })),
            budget,
            _memory: Arc::new(memory),
        })
    }
    pub fn begin(&self, request: &Request) -> Result<Step> {
        operation::validate(request)?;
        let mut s = self.state.lock().map_err(|_| Error::InternalFailure)?;
        if !s.live {
            return Err(Error::InvalidHandle);
        }
        let bound = match request {
            Request::Decrypt { handle, .. } | Request::ReplaceData { handle, .. } => Some(*handle),
            _ => None,
        };
        let id = next()?;
        let key = if let Some(handle) = bound {
            let k = s.contexts.get_mut(&handle).ok_or(Error::InvalidHandle)?;
            if k.busy.is_some() {
                return Err(Error::Busy);
            }
            // Binding is the consumption point, before the context check, per §8/9.
            k.busy = Some(id);
            Some(k.key.clone())
        } else {
            None
        };
        let prepared = (|| {
            let amount = operation::workspace(request)?
                .checked_add(if operation::needs_kdf(request) {
                    72 * 1024 * 1024
                } else {
                    0
                })
                .ok_or(Error::ResourceLimit)?;
            let memory = self.budget.reserve(amount)?;
            let slot = self.budget.slot(1)?;
            let context_count = match request {
                Request::Unlock { .. } => 1,
                Request::RecoverSelected { selection, .. } => selection.len(),
                _ => 0,
            };
            let mut reserved_contexts = Vec::with_capacity(context_count);
            for _ in 0..context_count {
                reserved_contexts.push((self.budget.slot(0)?, self.budget.reserve(4096)?));
            }
            if let Some(handle) = bound {
                let saved = &s.contexts.get(&handle).ok_or(Error::InvalidHandle)?.context;
                let matches =
                    match request {
                        Request::Decrypt { context, .. } => saved == context,
                        Request::ReplaceData {
                            source, purpose, ..
                        } => {
                            source.expected.target == saved.target
                                && *purpose == saved.purpose
                                && source.expected.purposes.iter().any(|p| {
                                    p.purpose == *purpose && p.generation == saved.generation
                                })
                        }
                        _ => false,
                    };
                if !matches {
                    return Err(Error::ContextMismatch);
                }
            }
            Ok(Operation {
                request: request.clone(),
                responses: Vec::new(),
                tape: Secret::default(),
                cache: Vec::new(),
                waiting: None,
                key,
                bound,
                reserved_contexts,
                _memory: memory,
                _slot: slot,
            })
        })();
        let op = match prepared {
            Ok(op) => op,
            Err(e) => {
                Self::finish_bound(&mut s, bound);
                return Err(e);
            }
        };
        let entry = Entry {
            operation: Arc::new(Mutex::new(op)),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        s.operations.insert(id, entry.clone());
        drop(s);
        self.drive(id, entry)
    }
    pub fn resume(
        &self,
        operation_id: u64,
        request_id: u64,
        response: &AdapterResponse,
    ) -> Result<Step> {
        let entry = {
            let s = self.state.lock().map_err(|_| Error::InternalFailure)?;
            s.operations
                .get(&operation_id)
                .cloned()
                .ok_or(Error::InvalidHandle)?
        };
        {
            let mut op = entry.operation.lock().map_err(|_| Error::InternalFailure)?;
            let Some((expected, kind)) = op.waiting else {
                return Err(Error::InvalidHandle);
            };
            if request_id != expected {
                return Err(Error::InvalidHandle);
            }
            if response.kind() != kind || operation::validate_response(response).is_err() {
                drop(op);
                self.fail(operation_id, &entry)?;
                return Err(Error::InvalidInput);
            }
            // Bounded response shapes are checked before the retained copy.
            op.responses.push(response.clone());
            op.waiting = None;
        }
        self.drive(operation_id, entry)
    }
    fn drive(&self, id: u64, entry: Entry) -> Result<Step> {
        let mut op = entry.operation.lock().map_err(|_| Error::InternalFailure)?;
        if entry.cancelled.load(Ordering::Acquire) {
            return Err(Error::InvalidHandle);
        }
        let crypto = match self.budget.crypto.try_lock() {
            Ok(lock) => lock,
            Err(_) => {
                drop(op);
                self.fail(id, &entry)?;
                return Err(Error::ResourceLimit);
            }
        };
        let Operation {
            request,
            responses,
            tape,
            key,
            cache,
            ..
        } = &mut *op;
        let draft = operation::run(
            request,
            responses,
            tape,
            &entry.cancelled,
            key.as_ref(),
            if cfg!(target_os = "android") {
                4
            } else if cfg!(target_os = "ios") {
                5
            } else {
                0
            },
            cache,
        );
        drop(crypto);
        let result = (|| {
            let mut state = self.state.lock().map_err(|_| Error::InternalFailure)?;
            if !state.live
                || entry.cancelled.load(Ordering::Acquire)
                || !state.operations.contains_key(&id)
            {
                return Err(Error::Cancelled);
            }
            match draft {
                Err(Halt::Pending(payload)) => {
                    let reservation = self.budget.reserve(16 * 1024)?;
                    let request_id = next()?;
                    let kind = payload.kind();
                    op.waiting = Some((request_id, kind));
                    Ok(Step {
                        value: StepValue::Pending {
                            operation_id: id,
                            requests: vec![AdapterRequest {
                                operation_id: id,
                                request_id,
                                payload: *payload,
                            }],
                        },
                        _reservation: reservation,
                    })
                }
                Err(Halt::Error(e)) => Err(e),
                Ok(draft) => {
                    let size = match &draft {
                        Draft::Candidate {
                            snapshot,
                            recovery_key,
                            ..
                        } => {
                            snapshot.capacity()
                                + recovery_key.as_ref().map_or(0, |v| v.0.capacity())
                        }
                        Draft::Plain(v) => v.0.capacity(),
                        _ => 0,
                    };
                    let reservation = self
                        .budget
                        .reserve(size.checked_add(512 * 1024).ok_or(Error::ResourceLimit)?)?;
                    let result = match draft {
                        Draft::Plain(plaintext) => Completed::Decrypt { plaintext },
                        Draft::Contexts { contexts, selected } => {
                            // IDs and all reservations are acquired before any handle is published.
                            let mut ids = Vec::with_capacity(contexts.len());
                            for _ in &contexts {
                                ids.push(next()?);
                            }
                            let mut recovered = Vec::with_capacity(contexts.len());
                            let reservations = std::mem::take(&mut op.reserved_contexts);
                            for (((context, key, lifetime), handle), (slot, memory)) in
                                contexts.into_iter().zip(ids).zip(reservations)
                            {
                                recovered.push((context.clone(), handle));
                                state.contexts.insert(
                                    handle,
                                    KeyContext {
                                        context,
                                        key,
                                        lifetime,
                                        busy: None,
                                        _slot: slot,
                                        _memory: memory,
                                    },
                                );
                            }
                            if selected {
                                Completed::RecoveredSelected {
                                    target: recovered[0].0.target.clone(),
                                    recovered,
                                }
                            } else {
                                Completed::Unlock {
                                    handle: recovered[0].1,
                                }
                            }
                        }
                        Draft::Candidate {
                            snapshot,
                            recovery_key,
                            invalidated,
                        } => {
                            let memory = self.budget.reserve(32 * 1024)?;
                            let slot = self.budget.slot(2)?;
                            let candidate_id = next()?;
                            let mut target = Vec::new();
                            format::visit_snapshot(&snapshot, |_, data, _| {
                                if target.is_empty() {
                                    target = format::data(data)?.target.to_vec();
                                }
                                Ok(())
                            })?;
                            let new_hash = crypto::hash(&snapshot);
                            let base_hash = source_snapshot(&op.request).map(crypto::hash);
                            state.candidates.insert(
                                candidate_id,
                                SavedCandidate {
                                    target,
                                    hash: new_hash,
                                    invalidated,
                                    _slot: slot,
                                    _memory: memory,
                                },
                            );
                            Completed::Candidate(Candidate {
                                id: candidate_id,
                                snapshot,
                                base_hash,
                                new_hash,
                                recovery_key,
                            })
                        }
                    };
                    state.operations.remove(&id);
                    Self::finish_bound(&mut state, op.bound);
                    Ok(Step {
                        value: StepValue::Completed {
                            request_tag: op.request.tag(),
                            result,
                        },
                        _reservation: reservation,
                    })
                }
            }
        })();
        if result.is_err() {
            drop(op);
            self.fail(id, &entry)?;
        }
        result
    }
    fn finish_bound(state: &mut State, bound: Option<u64>) {
        if let Some(handle) = bound {
            if state
                .contexts
                .get(&handle)
                .is_some_and(|k| k.lifetime == Lifetime::Operation)
            {
                state.contexts.remove(&handle);
            } else if let Some(k) = state.contexts.get_mut(&handle) {
                k.busy = None;
            }
        }
    }
    fn fail(&self, id: u64, entry: &Entry) -> Result<()> {
        entry.cancelled.store(true, Ordering::Release);
        let mut state = self.state.lock().map_err(|_| Error::InternalFailure)?;
        state.operations.remove(&id);
        let bound = state
            .contexts
            .iter()
            .find_map(|(h, k)| (k.busy == Some(id)).then_some(*h));
        Self::finish_bound(&mut state, bound);
        Ok(())
    }
    pub fn cancel(&self, operation_id: u64) -> Result<()> {
        let entry = {
            let state = self.state.lock().map_err(|_| Error::InternalFailure)?;
            state
                .operations
                .get(&operation_id)
                .cloned()
                .ok_or(Error::InvalidHandle)?
        };
        self.fail(operation_id, &entry)
    }
    pub fn release_context(&self, handle: u64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::InternalFailure)?;
        let k = state.contexts.remove(&handle).ok_or(Error::InvalidHandle)?;
        if let Some(id) = k.busy
            && let Some(e) = state.operations.remove(&id)
        {
            e.cancelled.store(true, Ordering::Release);
        }
        Ok(())
    }
    pub fn discard_candidate(&self, id: u64) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| Error::InternalFailure)?
            .candidates
            .remove(&id)
            .ok_or(Error::InvalidHandle)?;
        Ok(())
    }
    pub fn confirm_saved(&self, id: u64, new_hash: &[u8]) -> Result<()> {
        if new_hash.len() != 32 {
            return Err(Error::InvalidInput);
        }
        let mut s = self.state.lock().map_err(|_| Error::InternalFailure)?;
        let candidate = s.candidates.get(&id).ok_or(Error::InvalidHandle)?;
        if candidate.hash != new_hash {
            return Err(Error::ContextMismatch);
        }
        let _temporary = self.budget.reserve(32 * 1024)?;
        let target = candidate.target.clone();
        let invalidated = candidate.invalidated.clone();
        let mut cancelled = Vec::new();
        s.contexts.retain(|_, k| {
            let remove =
                k.context.target == target && invalidated.iter().any(|p| p == &k.context.purpose);
            if remove && let Some(op) = k.busy {
                cancelled.push(op);
            }
            !remove
        });
        for op in cancelled {
            if let Some(e) = s.operations.remove(&op) {
                e.cancelled.store(true, Ordering::Release);
            }
        }
        s.candidates.remove(&id);
        Ok(())
    }
    pub fn destroy(&self) -> Result<()> {
        let mut s = self.state.lock().map_err(|_| Error::InternalFailure)?;
        if !s.live {
            return Err(Error::InvalidHandle);
        }
        s.live = false;
        for e in s.operations.values() {
            e.cancelled.store(true, Ordering::Release);
        }
        s.operations.clear();
        s.contexts.clear();
        s.candidates.clear();
        Ok(())
    }
}
fn source_snapshot(r: &Request) -> Option<&[u8]> {
    match r {
        Request::AddPurpose { source, .. }
        | Request::RemovePurpose { source, .. }
        | Request::ReplaceData { source, .. }
        | Request::Rewrap { source, .. }
        | Request::RotateDek { source, .. }
        | Request::Recover { source, .. }
        | Request::ReissueRecovery { source, .. } => Some(&source.snapshot),
        _ => None,
    }
}
impl Vault {
    pub(crate) fn ffi_reserve(&self, size: usize) -> Result<Reservation> {
        self.budget.reserve(size)
    }
}
impl Vault {
    pub(crate) fn check_waiting(&self, id: u64, rid: u64) -> Result<()> {
        let entry = {
            let s = self.state.lock().map_err(|_| Error::InternalFailure)?;
            s.operations.get(&id).cloned().ok_or(Error::InvalidHandle)?
        };
        let op = entry.operation.lock().map_err(|_| Error::InternalFailure)?;
        if op.waiting.is_some_and(|(expected, _)| expected == rid)
            && !entry.cancelled.load(Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(Error::InvalidHandle)
        }
    }
}
