use base64ct::{Base64UrlUnpadded, Encoding};
use getrandom::getrandom;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::config::SHAMIR_MIN_PRIME_BITS;
use crate::error::Shamir3PassError;

const PRIME_GEN_MAX_ATTEMPTS: usize = 10_000;
const MILLER_RABIN_ROUNDS: usize = 32;

/// Extended Euclidean algorithm.
pub fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a, BigInt::one(), BigInt::zero());
    }

    let (gcd, x1, y1) = extended_gcd(b.clone(), &a % &b);
    let x = y1.clone();
    let y = x1 - (&a / &b) * y1;

    (gcd, x, y)
}

/// Encode BigUint as base64url (unpadded).
pub fn encode_biguint_b64u(x: &BigUint) -> String {
    Base64UrlUnpadded::encode_string(&x.to_bytes_be())
}

/// Decode BigUint from base64url (unpadded).
pub fn decode_biguint_b64u(s: &str) -> Result<BigUint, base64ct::Error> {
    let bytes = Base64UrlUnpadded::decode_vec(s)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Generate a random prime modulus `p` (base64url, unpadded) for Shamir 3-pass.
///
/// `p` is a public parameter and MUST be shared by both parties; generate it once,
/// persist it, and distribute it to clients.
pub fn generate_shamir_p_b64u(bits: usize) -> Result<String, Shamir3PassError> {
    let p = generate_shamir_p(bits)?;
    Ok(Base64UrlUnpadded::encode_string(&p.to_bytes_be()))
}

/// Generate a random prime modulus `p` as a `BigUint`.
pub fn generate_shamir_p(bits: usize) -> Result<BigUint, Shamir3PassError> {
    if bits < SHAMIR_MIN_PRIME_BITS {
        return Err(Shamir3PassError::PrimeTooSmall {
            bits,
            min_bits: SHAMIR_MIN_PRIME_BITS,
        });
    }

    let bytes_len = (bits + 7) / 8;
    let top_bits = bits % 8;

    for _ in 0..PRIME_GEN_MAX_ATTEMPTS {
        let mut buf = vec![0u8; bytes_len];
        getrandom(&mut buf).map_err(|_| Shamir3PassError::RandomGenerationFailed)?;

        // Ensure the generated number has exactly `bits` bits (set the MSB).
        if top_bits != 0 {
            let mask = (1u8 << top_bits) - 1;
            buf[0] &= mask;
            buf[0] |= 1u8 << (top_bits - 1);
        } else {
            buf[0] |= 0x80;
        }

        // Ensure odd.
        buf[bytes_len - 1] |= 1;

        let n = BigUint::from_bytes_be(&buf);
        if is_probably_prime(&n)? {
            return Ok(n);
        }
    }

    Err(Shamir3PassError::RandomGenerationFailed)
}

pub(crate) fn gcd_biguint(a: &BigUint, b: &BigUint) -> BigUint {
    let mut x = a.clone();
    let mut y = b.clone();
    while !y.is_zero() {
        let r = &x % &y;
        x = y;
        y = r;
    }
    x
}

fn is_probably_prime(n: &BigUint) -> Result<bool, Shamir3PassError> {
    let one = BigUint::one();
    let two = &one + &one;
    let three = &two + &one;

    if n < &two {
        return Ok(false);
    }
    if n == &two || n == &three {
        return Ok(true);
    }
    if (n % &two).is_zero() {
        return Ok(false);
    }

    // Quick trial division by a few small primes.
    const SMALL_PRIMES: [u32; 11] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for p in SMALL_PRIMES {
        let p = BigUint::from(p);
        if n == &p {
            return Ok(true);
        }
        if (n % &p).is_zero() {
            return Ok(false);
        }
    }

    // Write n-1 as d * 2^s with d odd.
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s: u32 = 0;
    while (&d % &two).is_zero() {
        d >>= 1;
        s += 1;
    }

    // Miller-Rabin rounds with random bases.
    for _ in 0..MILLER_RABIN_ROUNDS {
        let a = random_biguint_below(&(n - &three))? + &two; // a ∈ [2, n-2]
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }

        let mut passed = false;
        for _ in 1..s {
            x = (&x * &x) % n;
            if x == n_minus_1 {
                passed = true;
                break;
            }
            if x == one {
                return Ok(false);
            }
        }

        if !passed {
            return Ok(false);
        }
    }

    Ok(true)
}

fn random_biguint_below(upper: &BigUint) -> Result<BigUint, Shamir3PassError> {
    if upper.is_zero() {
        return Ok(BigUint::zero());
    }

    // Rejection-sample uniformly in [0, upper).
    //
    // This avoids modulo bias, which matters for Miller–Rabin error bounds when using
    // random bases.
    let bits = upper.bits() as usize;
    let bytes_len = (bits + 7) / 8;
    let top_bits = bits % 8;

    loop {
        let mut buf = vec![0u8; bytes_len];
        getrandom(&mut buf).map_err(|_| Shamir3PassError::RandomGenerationFailed)?;

        if top_bits != 0 {
            let mask = (1u8 << top_bits) - 1;
            buf[0] &= mask;
        }

        let n = BigUint::from_bytes_be(&buf);
        if &n < upper {
            return Ok(n);
        }
    }
}
