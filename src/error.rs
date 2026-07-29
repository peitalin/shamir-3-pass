#[derive(Debug)]
pub enum Shamir3PassError {
    InvalidPrime(String),
    PrimeTooSmall { bits: usize, min_bits: usize },
    InvalidGroupElement(String),
    InvalidLockKey(String),
    EmptyDerivationContext,
    KeyDerivationFailed,
    ModularInverseNotFound,
    RandomGenerationFailed,
    EncryptionFailed(String),
    DecryptionFailed(String),
}

impl std::error::Error for Shamir3PassError {}

impl core::fmt::Display for Shamir3PassError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Shamir3PassError::InvalidPrime(msg) => write!(f, "invalid prime: {}", msg),
            Shamir3PassError::PrimeTooSmall { bits, min_bits } => {
                write!(f, "prime too small (bits={}, min_bits={})", bits, min_bits)
            }
            Shamir3PassError::InvalidGroupElement(msg) => {
                write!(f, "invalid group element: {}", msg)
            }
            Shamir3PassError::InvalidLockKey(msg) => write!(f, "invalid lock key: {}", msg),
            Shamir3PassError::EmptyDerivationContext => {
                write!(f, "lock-key derivation context must be non-empty")
            }
            Shamir3PassError::KeyDerivationFailed => write!(f, "lock-key derivation failed"),
            Shamir3PassError::ModularInverseNotFound => write!(f, "modular inverse not found"),
            Shamir3PassError::RandomGenerationFailed => write!(f, "random generation failed"),
            Shamir3PassError::EncryptionFailed(msg) => write!(f, "encryption failed: {}", msg),
            Shamir3PassError::DecryptionFailed(msg) => write!(f, "decryption failed: {}", msg),
        }
    }
}
