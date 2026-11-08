//! Chain-independent Vault v1. See vault-docs/docs/specifications/rust-vault.md.
pub mod abi;
mod budget;
mod crypto;
mod engine;
pub mod ffi;
pub mod format;
mod model;
mod operation;

pub use engine::Vault;
pub use model::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    InvalidInput = 1,
    Unsupported = 2,
    ContextMismatch = 3,
    VerificationFailed = 4,
    RandomFailure = 5,
    Cancelled = 6,
    KeyInvalidated = 7,
    InvalidHandle = 8,
    Busy = 9,
    InternalFailure = 10,
    ResourceLimit = 11,
    AuthenticationFailed = 12,
    AuthenticationLockedOut = 13,
    AdapterFailure = 14,
}
pub type Result<T> = std::result::Result<T, Error>;
#[cfg(target_arch = "wasm32")]
mod wasm;
