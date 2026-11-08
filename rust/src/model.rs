use crate::{Error, Result};
use zeroize::{Zeroize, Zeroizing};

/// Secret bytes deliberately have a redacted Debug representation.
#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct Secret(pub Vec<u8>);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    pub target: Vec<u8>,
    pub purpose: Vec<u8>,
    pub generation: u64,
}
impl Context {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::format::id(&self.target)?;
        crate::format::id(&self.purpose)?;
        if self.generation == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expectation {
    pub purpose: Vec<u8>,
    pub generation: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedSnapshot {
    pub target: Vec<u8>,
    pub purposes: Vec<Expectation>,
}
#[derive(Clone)]
pub struct Source {
    pub snapshot: Vec<u8>,
    pub expected: ExpectedSnapshot,
}
#[derive(Clone)]
pub struct RoutePlan {
    pub action: u32,
    pub kind: u32,
    pub source_route_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub protection: u32,
}
#[derive(Clone, Debug)]
pub struct PurposePlan {
    pub purpose: Vec<u8>,
    pub routes: Vec<RoutePlan>,
}
#[derive(Clone, Debug)]
pub struct PurposeInput {
    pub plan: PurposePlan,
    pub plaintext: Secret,
}
#[derive(Clone, Debug)]
pub struct UnlockRoute {
    pub purpose: Vec<u8>,
    pub route: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct SelectionInput {
    pub context: Context,
    pub data: Vec<u8>,
    pub recovery_wrap: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Lifetime {
    Operation = 1,
    Explicit = 2,
}
#[derive(Clone)]
pub enum Request {
    Create {
        target: Vec<u8>,
        purposes: Vec<PurposeInput>,
    },
    AddPurpose {
        source: Source,
        purpose: PurposeInput,
    },
    RemovePurpose {
        source: Source,
        purposes: Vec<Vec<u8>>,
    },
    Unlock {
        context: Context,
        data: Vec<u8>,
        wrap: Vec<u8>,
        lifetime: Lifetime,
    },
    Decrypt {
        handle: u64,
        context: Context,
        data: Vec<u8>,
    },
    ReplaceData {
        source: Source,
        handle: u64,
        purpose: Vec<u8>,
        plaintext: Secret,
    },
    Rewrap {
        source: Source,
        plans: Vec<PurposePlan>,
        fresh_unlock_routes: Vec<UnlockRoute>,
    },
    RotateDek {
        source: Source,
        plans: Vec<PurposePlan>,
        fresh_unlock_routes: Vec<UnlockRoute>,
    },
    Recover {
        source: Source,
        plans: Vec<PurposePlan>,
    },
    ReissueRecovery {
        source: Source,
        fresh_unlock_routes: Vec<UnlockRoute>,
    },
    RecoverSelected {
        selection: Vec<SelectionInput>,
        lifetime: Lifetime,
    },
}
impl Request {
    pub fn tag(&self) -> u32 {
        match self {
            Self::Create { .. } => 1,
            Self::AddPurpose { .. } => 2,
            Self::RemovePurpose { .. } => 3,
            Self::Unlock { .. } => 4,
            Self::Decrypt { .. } => 5,
            Self::ReplaceData { .. } => 6,
            Self::Rewrap { .. } => 7,
            Self::RotateDek { .. } => 8,
            Self::Recover { .. } => 9,
            Self::ReissueRecovery { .. } => 10,
            Self::RecoverSelected { .. } => 11,
        }
    }
}
#[derive(Clone)]
pub enum AdapterPayload {
    Password {
        context: Context,
        route: Vec<u8>,
        for_protection: bool,
    },
    Recovery {
        expected: ExpectedSnapshot,
    },
    Prf {
        context: Context,
        route: Vec<u8>,
        credential_id: Vec<u8>,
        input: Vec<u8>,
    },
    AndroidPrepare {
        context: Context,
        route: Vec<u8>,
        protection: u32,
    },
    AndroidEncrypt {
        context: Context,
        route: Vec<u8>,
        key_ref: Vec<u8>,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        dek: Secret,
    },
    AndroidDecrypt {
        context: Context,
        route: Vec<u8>,
        key_ref: Vec<u8>,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    IosPrepare {
        context: Context,
        route: Vec<u8>,
    },
    IosEncrypt {
        context: Context,
        route: Vec<u8>,
        key_ref: Vec<u8>,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
        dek: Secret,
    },
    IosDecrypt {
        context: Context,
        route: Vec<u8>,
        key_ref: Vec<u8>,
        ephemeral_public_key: Vec<u8>,
        salt: Vec<u8>,
        nonce: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    },
}
impl AdapterPayload {
    pub fn kind(&self) -> u32 {
        match self {
            Self::Password { .. } => 1,
            Self::Recovery { .. } => 2,
            Self::Prf { .. } => 3,
            Self::AndroidPrepare { .. } => 4,
            Self::AndroidEncrypt { .. } => 5,
            Self::AndroidDecrypt { .. } => 6,
            Self::IosPrepare { .. } => 7,
            Self::IosEncrypt { .. } => 8,
            Self::IosDecrypt { .. } => 9,
        }
    }
}
#[derive(Clone)]
pub struct AdapterRequest {
    pub operation_id: u64,
    pub request_id: u64,
    pub payload: AdapterPayload,
}
#[derive(Clone)]
pub enum AdapterResponse {
    Password(Secret),
    Recovery(Secret),
    Prf(Secret),
    AndroidPrepared {
        key_ref: Vec<u8>,
        protection: u32,
        nonce: Vec<u8>,
    },
    AndroidEncrypted(Vec<u8>),
    AndroidDecrypted(Secret),
    IosPrepared {
        key_ref: Vec<u8>,
        ephemeral_public_key: Vec<u8>,
    },
    IosEncrypted(Vec<u8>),
    IosDecrypted(Secret),
    Failure {
        kind: u32,
        error: Error,
    },
}
impl AdapterResponse {
    pub fn kind(&self) -> u32 {
        match self {
            Self::Password(_) => 1,
            Self::Recovery(_) => 2,
            Self::Prf(_) => 3,
            Self::AndroidPrepared { .. } => 4,
            Self::AndroidEncrypted(_) => 5,
            Self::AndroidDecrypted(_) => 6,
            Self::IosPrepared { .. } => 7,
            Self::IosEncrypted(_) => 8,
            Self::IosDecrypted(_) => 9,
            Self::Failure { kind, .. } => *kind,
        }
    }
}
#[derive(Clone)]
pub struct Candidate {
    pub id: u64,
    pub snapshot: Vec<u8>,
    pub base_hash: Option<[u8; 32]>,
    pub new_hash: [u8; 32],
    pub recovery_key: Option<Secret>,
}
#[derive(Clone, Debug)]
pub enum Completed {
    Unlock {
        handle: u64,
    },
    Decrypt {
        plaintext: Secret,
    },
    Candidate(Candidate),
    RecoveredSelected {
        target: Vec<u8>,
        recovered: Vec<(Context, u64)>,
    },
}
#[derive(Clone, Debug)]
pub enum StepValue {
    Completed {
        request_tag: u32,
        result: Completed,
    },
    Pending {
        operation_id: u64,
        requests: Vec<AdapterRequest>,
    },
}
/// Dropping the result releases its reservation independently of the Vault lifetime.
pub struct Step {
    pub(crate) value: StepValue,
    pub(crate) _reservation: crate::budget::Reservation,
}
impl std::fmt::Debug for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}
pub(crate) type Key = Zeroizing<[u8; 32]>;

impl Step {
    pub fn value(&self) -> &StepValue {
        &self.value
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("snapshot_len", &self.snapshot.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for RoutePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutePlan")
            .field("action", &self.action)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("tag", &self.tag())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for AdapterPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterPayload")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for AdapterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterRequest")
            .field("operation_id", &self.operation_id)
            .field("request_id", &self.request_id)
            .field("kind", &self.payload.kind())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for AdapterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterResponse")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate")
            .field("id", &self.id)
            .field("snapshot_len", &self.snapshot.len())
            .finish_non_exhaustive()
    }
}
