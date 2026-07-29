//! Typed Shamir three-pass protocol operations.
//!
//! Secret exponents are kept behind [`LockKeyPair`]. The underlying
//! `num-bigint` modular exponentiation is variable-time, so this crate is not
//! suitable where local timing or cache side channels are in scope.

#[cfg(feature = "aead")]
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, Key},
    ChaCha20Poly1305, KeyInit,
};
use getrandom::getrandom;
use hkdf::Hkdf;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::One;
use sha2::Sha256;
use zeroize::Zeroizing;

#[cfg(feature = "aead")]
use crate::config::SHAMIR_AEAD_HKDF_INFO;
use crate::config::{
    RFC3526_GROUP14_MODULUS_HEX, SHAMIR_LOCK_KEY_DERIVATION_SALT, SHAMIR_MIN_SAFE_PRIME_BITS,
    SHAMIR_REJECTION_SAMPLING_MAX_ATTEMPTS,
};
use crate::error::Shamir3PassError;
use crate::utils::{decode_biguint_b64u, encode_biguint_b64u, extended_gcd, gcd_biguint};

const MIN_EXPONENT: u128 = 1u128 << 64;
const DERIVATION_INFO_PREFIX: &[u8] = b"shamir-3-pass/lock-key-pair/v1";

/// A reviewed, built-in safe-prime group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModpGroup {
    /// RFC 3526 2048-bit MODP Group (group 14).
    Rfc3526Group14,
}

impl ModpGroup {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Rfc3526Group14 => "rfc3526-group14",
        }
    }
}

/// A value checked to be in the active group's accepted range.
#[derive(Clone, Eq, PartialEq)]
pub struct GroupElement(BigUint);

impl GroupElement {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }

    pub fn to_b64u(&self) -> String {
        encode_biguint_b64u(&self.0)
    }
}

/// Serialized secret exponents for storage at a secrets boundary.
pub struct LockKeyPairBytes {
    add_exponent: Zeroizing<Vec<u8>>,
    remove_exponent: Zeroizing<Vec<u8>>,
}

impl LockKeyPairBytes {
    pub fn new(add_exponent: Vec<u8>, remove_exponent: Vec<u8>) -> Self {
        Self {
            add_exponent: Zeroizing::new(add_exponent),
            remove_exponent: Zeroizing::new(remove_exponent),
        }
    }

    pub fn add_exponent(&self) -> &[u8] {
        self.add_exponent.as_slice()
    }

    pub fn remove_exponent(&self) -> &[u8] {
        self.remove_exponent.as_slice()
    }
}

/// An opaque pair of inverse exponents used to add and remove one lock.
pub struct LockKeyPair {
    add_exponent: Zeroizing<Vec<u8>>,
    remove_exponent: Zeroizing<Vec<u8>>,
}

impl LockKeyPair {
    pub fn add_lock(&self, protocol: &Shamir3Pass, value: &GroupElement) -> GroupElement {
        protocol.apply_exponent(value, self.add_exponent.as_slice())
    }

    pub fn remove_lock(&self, protocol: &Shamir3Pass, value: &GroupElement) -> GroupElement {
        protocol.apply_exponent(value, self.remove_exponent.as_slice())
    }

    pub fn export_secret(&self) -> LockKeyPairBytes {
        LockKeyPairBytes::new(self.add_exponent.to_vec(), self.remove_exponent.to_vec())
    }
}

/// Public parameters and checked operations for Shamir three-pass.
#[derive(Clone, Eq, PartialEq)]
pub struct Shamir3Pass {
    group_id: Option<&'static str>,
    p: BigUint,
    p_minus_1: BigUint,
    max_value: BigUint,
    min_exponent: BigUint,
}

impl Shamir3Pass {
    /// Construct the protocol with reviewed built-in parameters.
    pub fn from_group(group: ModpGroup) -> Self {
        let p = match group {
            ModpGroup::Rfc3526Group14 => {
                BigUint::parse_bytes(RFC3526_GROUP14_MODULUS_HEX.as_bytes(), 16)
                    .expect("RFC 3526 group 14 constant must be valid hexadecimal")
            }
        };
        Self::from_validated_prime(p, Some(group.id()))
    }

    /// Construct the protocol from a base64url-encoded custom safe prime.
    ///
    /// This boundary performs probabilistic primality checks on both `p` and
    /// `(p - 1) / 2`. Prefer [`Self::from_group`] when custom parameters are not
    /// required.
    pub fn from_safe_prime_b64u(value: &str) -> Result<Self, Shamir3PassError> {
        let p = decode_biguint_b64u(value).map_err(|_| {
            Shamir3PassError::InvalidPrime("invalid base64url encoding".to_string())
        })?;
        Self::from_safe_prime(p)
    }

    /// Construct the protocol from a custom safe prime.
    pub fn from_safe_prime(p: BigUint) -> Result<Self, Shamir3PassError> {
        let bits = p.bits() as usize;
        if bits < SHAMIR_MIN_SAFE_PRIME_BITS {
            return Err(Shamir3PassError::PrimeTooSmall {
                bits,
                min_bits: SHAMIR_MIN_SAFE_PRIME_BITS,
            });
        }
        if !crate::utils::is_safe_prime(&p)? {
            return Err(Shamir3PassError::InvalidPrime(
                "modulus must be a safe prime".to_string(),
            ));
        }
        Ok(Self::from_validated_prime(p, None))
    }

    fn from_validated_prime(p: BigUint, group_id: Option<&'static str>) -> Self {
        let one = BigUint::one();
        let p_minus_1 = &p - &one;
        let max_value = &p_minus_1 - &one;
        Self {
            group_id,
            p,
            p_minus_1,
            max_value,
            min_exponent: BigUint::from(MIN_EXPONENT),
        }
    }

    pub fn group_id(&self) -> Option<&'static str> {
        self.group_id
    }

    pub fn modulus_b64u(&self) -> String {
        encode_biguint_b64u(&self.p)
    }

    pub fn element_from_bytes(&self, bytes: &[u8]) -> Result<GroupElement, Shamir3PassError> {
        self.checked_element(BigUint::from_bytes_be(bytes))
    }

    pub fn element_from_b64u(&self, value: &str) -> Result<GroupElement, Shamir3PassError> {
        let value = decode_biguint_b64u(value).map_err(|_| {
            Shamir3PassError::InvalidGroupElement("invalid base64url encoding".to_string())
        })?;
        self.checked_element(value)
    }

    fn checked_element(&self, value: BigUint) -> Result<GroupElement, Shamir3PassError> {
        if value < BigUint::from(2u8) || value > self.max_value {
            return Err(Shamir3PassError::InvalidGroupElement(
                "value must be in [2, p - 2]".to_string(),
            ));
        }
        Ok(GroupElement(value))
    }

    pub fn generate_lock_key_pair(&self) -> Result<LockKeyPair, Shamir3PassError> {
        let exponent = self.random_invertible_exponent()?;
        self.key_pair_from_add_exponent(exponent)
    }

    /// Deterministically derive a lock-key pair from a 32-byte root secret.
    ///
    /// Use a stable, non-empty context that uniquely names the deployment and
    /// key role. Changing either the root or context produces a different pair.
    pub fn derive_lock_key_pair(
        &self,
        root_secret: &[u8; 32],
        context: &[u8],
    ) -> Result<LockKeyPair, Shamir3PassError> {
        if context.is_empty() {
            return Err(Shamir3PassError::EmptyDerivationContext);
        }

        let hkdf = Hkdf::<Sha256>::new(Some(SHAMIR_LOCK_KEY_DERIVATION_SALT), root_secret);
        let bytes_len = self.p.to_bytes_be().len();
        for attempt in 0..SHAMIR_REJECTION_SAMPLING_MAX_ATTEMPTS {
            let mut info = Vec::with_capacity(DERIVATION_INFO_PREFIX.len() + context.len() + 12);
            info.extend_from_slice(DERIVATION_INFO_PREFIX);
            info.extend_from_slice(&(context.len() as u64).to_be_bytes());
            info.extend_from_slice(context);
            info.extend_from_slice(&(attempt as u32).to_be_bytes());

            let mut output = Zeroizing::new(vec![0u8; bytes_len]);
            hkdf.expand(&info, output.as_mut_slice())
                .map_err(|_| Shamir3PassError::KeyDerivationFailed)?;
            let candidate = BigUint::from_bytes_be(output.as_slice());
            if self.is_valid_exponent(&candidate) {
                return self.key_pair_from_add_exponent(candidate);
            }
        }
        Err(Shamir3PassError::KeyDerivationFailed)
    }

    pub fn import_lock_key_pair(
        &self,
        encoded: &LockKeyPairBytes,
    ) -> Result<LockKeyPair, Shamir3PassError> {
        let add = BigUint::from_bytes_be(encoded.add_exponent());
        let remove = BigUint::from_bytes_be(encoded.remove_exponent());
        if !self.is_valid_exponent(&add) || !self.is_valid_exponent(&remove) {
            return Err(Shamir3PassError::InvalidLockKey(
                "exponents are outside the valid range or not invertible".to_string(),
            ));
        }
        if (&add * &remove) % &self.p_minus_1 != BigUint::one() {
            return Err(Shamir3PassError::InvalidLockKey(
                "remove exponent is not the inverse of add exponent".to_string(),
            ));
        }
        Ok(Self::lock_key_pair(add, remove))
    }

    fn key_pair_from_add_exponent(&self, add: BigUint) -> Result<LockKeyPair, Shamir3PassError> {
        let remove = self
            .mod_inverse(&add)
            .ok_or(Shamir3PassError::ModularInverseNotFound)?;
        Ok(Self::lock_key_pair(add, remove))
    }

    fn lock_key_pair(add: BigUint, remove: BigUint) -> LockKeyPair {
        LockKeyPair {
            add_exponent: Zeroizing::new(add.to_bytes_be()),
            remove_exponent: Zeroizing::new(remove.to_bytes_be()),
        }
    }

    fn random_invertible_exponent(&self) -> Result<BigUint, Shamir3PassError> {
        let bytes_len = self.p.to_bytes_be().len();
        for _ in 0..SHAMIR_REJECTION_SAMPLING_MAX_ATTEMPTS {
            let mut bytes = Zeroizing::new(vec![0u8; bytes_len]);
            getrandom(bytes.as_mut_slice())
                .map_err(|_| Shamir3PassError::RandomGenerationFailed)?;
            let candidate = BigUint::from_bytes_be(bytes.as_slice());
            if self.is_valid_exponent(&candidate) {
                return Ok(candidate);
            }
        }
        Err(Shamir3PassError::RandomGenerationFailed)
    }

    fn is_valid_exponent(&self, value: &BigUint) -> bool {
        value >= &self.min_exponent
            && value <= &self.max_value
            && gcd_biguint(value, &self.p_minus_1) == BigUint::one()
    }

    fn mod_inverse(&self, value: &BigUint) -> Option<BigUint> {
        let value = BigInt::from_biguint(Sign::Plus, value.clone());
        let modulus = BigInt::from_biguint(Sign::Plus, self.p_minus_1.clone());
        let (gcd, inverse, _) = extended_gcd(value, modulus.clone());
        if gcd != BigInt::one() {
            return None;
        }
        let inverse = ((inverse % &modulus) + &modulus) % &modulus;
        inverse.to_biguint()
    }

    fn apply_exponent(&self, value: &GroupElement, exponent: &[u8]) -> GroupElement {
        let exponent = BigUint::from_bytes_be(exponent);
        GroupElement(value.0.modpow(&exponent, &self.p))
    }

    #[cfg(feature = "aead")]
    pub fn encrypt_with_random_kek(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, GroupElement), Shamir3PassError> {
        let kek = self.random_group_element()?;
        let ciphertext = self.encrypt_with_kek(&kek, plaintext)?;
        Ok((ciphertext, kek))
    }

    #[cfg(feature = "aead")]
    pub fn decrypt_with_kek(
        &self,
        ciphertext: &[u8],
        kek: &GroupElement,
    ) -> Result<Vec<u8>, Shamir3PassError> {
        if ciphertext.len() < 12 {
            return Err(Shamir3PassError::DecryptionFailed(
                "ciphertext too short".to_string(),
            ));
        }
        let key = self.derive_aead_key(kek)?;
        let cipher = ChaCha20Poly1305::new(Key::<ChaCha20Poly1305>::from_slice(&key));
        let (nonce, body) = ciphertext.split_at(12);
        cipher
            .decrypt(GenericArray::from_slice(nonce), body)
            .map_err(|_| Shamir3PassError::DecryptionFailed("authentication failed".to_string()))
    }

    #[cfg(feature = "aead")]
    fn encrypt_with_kek(
        &self,
        kek: &GroupElement,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Shamir3PassError> {
        let key = self.derive_aead_key(kek)?;
        let cipher = ChaCha20Poly1305::new(Key::<ChaCha20Poly1305>::from_slice(&key));
        let mut nonce = [0u8; 12];
        getrandom(&mut nonce).map_err(|_| Shamir3PassError::RandomGenerationFailed)?;
        let body = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext)
            .map_err(|_| Shamir3PassError::EncryptionFailed("encryption failed".to_string()))?;
        let mut ciphertext = nonce.to_vec();
        ciphertext.extend_from_slice(&body);
        Ok(ciphertext)
    }

    #[cfg(feature = "aead")]
    fn derive_aead_key(&self, kek: &GroupElement) -> Result<[u8; 32], Shamir3PassError> {
        let kek_bytes = Zeroizing::new(kek.to_bytes());
        let hkdf = Hkdf::<Sha256>::new(None, kek_bytes.as_slice());
        let mut key = [0u8; 32];
        hkdf.expand(SHAMIR_AEAD_HKDF_INFO, &mut key)
            .map_err(|_| Shamir3PassError::EncryptionFailed("HKDF expansion failed".to_string()))?;
        Ok(key)
    }

    #[cfg(feature = "aead")]
    fn random_group_element(&self) -> Result<GroupElement, Shamir3PassError> {
        let bytes_len = self.p.to_bytes_be().len();
        for _ in 0..SHAMIR_REJECTION_SAMPLING_MAX_ATTEMPTS {
            let mut bytes = Zeroizing::new(vec![0u8; bytes_len]);
            getrandom(bytes.as_mut_slice())
                .map_err(|_| Shamir3PassError::RandomGenerationFailed)?;
            let candidate = BigUint::from_bytes_be(bytes.as_slice());
            if let Ok(value) = self.checked_element(candidate) {
                return Ok(value);
            }
        }
        Err(Shamir3PassError::RandomGenerationFailed)
    }
}
