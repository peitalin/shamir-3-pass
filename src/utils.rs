use base64ct::{Base64UrlUnpadded, Encoding};
use getrandom::getrandom;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use crate::error::Shamir3PassError;

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

/// Encode an unsigned integer as unpadded base64url.
pub fn encode_biguint_b64u(value: &BigUint) -> String {
    Base64UrlUnpadded::encode_string(&value.to_bytes_be())
}

/// Decode an unsigned integer from unpadded base64url.
pub fn decode_biguint_b64u(value: &str) -> Result<BigUint, base64ct::Error> {
    let bytes = Base64UrlUnpadded::decode_vec(value)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

pub(crate) fn gcd_biguint(a: &BigUint, b: &BigUint) -> BigUint {
    let mut x = a.clone();
    let mut y = b.clone();
    while !y.is_zero() {
        let remainder = &x % &y;
        x = y;
        y = remainder;
    }
    x
}

pub(crate) fn is_safe_prime(value: &BigUint) -> Result<bool, Shamir3PassError> {
    if !is_probably_prime(value)? {
        return Ok(false);
    }
    let q = (value - BigUint::one()) >> 1;
    is_probably_prime(&q)
}

pub(crate) fn is_probably_prime(value: &BigUint) -> Result<bool, Shamir3PassError> {
    let one = BigUint::one();
    let two = BigUint::from(2u8);
    let three = BigUint::from(3u8);
    if value < &two {
        return Ok(false);
    }
    if value == &two || value == &three {
        return Ok(true);
    }
    if (value % &two).is_zero() {
        return Ok(false);
    }

    const SMALL_PRIMES: [u32; 11] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for small_prime in SMALL_PRIMES {
        let small_prime = BigUint::from(small_prime);
        if value == &small_prime {
            return Ok(true);
        }
        if (value % &small_prime).is_zero() {
            return Ok(false);
        }
    }

    let value_minus_one = value - &one;
    let mut odd_factor = value_minus_one.clone();
    let mut power_of_two = 0u32;
    while (&odd_factor % &two).is_zero() {
        odd_factor >>= 1;
        power_of_two += 1;
    }

    for _ in 0..MILLER_RABIN_ROUNDS {
        let base = random_biguint_below(&(value - &three))? + &two;
        let mut witness = base.modpow(&odd_factor, value);
        if witness == one || witness == value_minus_one {
            continue;
        }

        let mut probably_prime = false;
        for _ in 1..power_of_two {
            witness = (&witness * &witness) % value;
            if witness == value_minus_one {
                probably_prime = true;
                break;
            }
            if witness == one {
                return Ok(false);
            }
        }
        if !probably_prime {
            return Ok(false);
        }
    }
    Ok(true)
}

fn random_biguint_below(upper: &BigUint) -> Result<BigUint, Shamir3PassError> {
    if upper.is_zero() {
        return Ok(BigUint::zero());
    }
    let bits = upper.bits() as usize;
    let bytes_len = bits.div_ceil(8);
    let top_bits = bits % 8;
    loop {
        let mut bytes = vec![0u8; bytes_len];
        getrandom(&mut bytes).map_err(|_| Shamir3PassError::RandomGenerationFailed)?;
        if top_bits != 0 {
            bytes[0] &= (1u8 << top_bits) - 1;
        }
        let candidate = BigUint::from_bytes_be(&bytes);
        if &candidate < upper {
            return Ok(candidate);
        }
    }
}
