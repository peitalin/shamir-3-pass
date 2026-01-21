//! Shamir 3-pass protocol library.
//!
//! This crate contains a small, self-contained implementation of the Shamir 3-pass
//! commutative encryption protocol, suitable for both native and `wasm32` targets.

pub mod config;
pub mod error;
pub mod shamir3pass;
pub mod utils;

#[cfg(test)]
pub mod tests;

pub use crate::error::Shamir3PassError;
pub use crate::shamir3pass::{ClientLockKeys, Shamir3Pass};
pub use crate::utils::{decode_biguint_b64u, encode_biguint_b64u};
pub use crate::utils::{generate_shamir_p, generate_shamir_p_b64u};
