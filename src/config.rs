//! Library configuration and protocol parameters.

/// Minimum acceptable size (in bits) for a prime modulus `p`.
pub const SHAMIR_MIN_PRIME_BITS: usize = 256;

/// Extra bytes mixed into rejection sampling to reduce modulo bias.
pub const SHAMIR_RANDOM_BYTES_OVERHEAD: u64 = 16;

/// Maximum attempts for generating an invertible exponent (gcd(k, p-1) = 1).
pub const SHAMIR_REJECTION_SAMPLING_MAX_ATTEMPTS: usize = 128;

/// HKDF info label for deriving the AEAD key from the KEK.
pub const SHAMIR_AEAD_HKDF_INFO: &[u8] = b"shamir3pass-kek-aead-v1";
