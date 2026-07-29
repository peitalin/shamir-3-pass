//! Shamir 3-pass protocol library.
//!
//! This crate contains a small, self-contained implementation of the Shamir 3-pass
//! commutative encryption protocol, suitable for both native and `wasm32` targets.

mod config;
mod error;
mod shamir3pass;
mod utils;

#[cfg(test)]
mod tests;

pub use crate::error::Shamir3PassError;
pub use crate::shamir3pass::{GroupElement, LockKeyPair, LockKeyPairBytes, ModpGroup, Shamir3Pass};
pub use crate::utils::{decode_biguint_b64u, encode_biguint_b64u};
