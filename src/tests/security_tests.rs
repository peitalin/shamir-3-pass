use std::collections::HashSet;

use super::shamir;
use crate::LockKeyPairBytes;

#[test]
fn generated_lock_key_pairs_are_distinct() {
    let protocol = shamir();
    let mut add_exponents = HashSet::new();

    // Generate several pairs and reject any collision in their add exponents.
    for _ in 0..32 {
        let encoded = protocol.generate_lock_key_pair().unwrap().export_secret();
        assert!(add_exponents.insert(encoded.add_exponent().to_vec()));
    }
}

#[test]
fn imported_pair_must_contain_inverse_exponents() {
    let protocol = shamir();
    let invalid = LockKeyPairBytes::new(vec![3], vec![5]);

    // Import validates that add * remove = 1 mod (p - 1).
    assert!(protocol.import_lock_key_pair(&invalid).is_err());
}

#[cfg(feature = "aead")]
#[test]
fn optional_aead_detects_tampering_and_wrong_keys() {
    let protocol = shamir();
    let (mut ciphertext, kek) = protocol.encrypt_with_random_kek(b"authentic").unwrap();
    let (_, wrong_kek) = protocol.encrypt_with_random_kek(b"other").unwrap();

    // Authentication must fail when a different KEK is supplied.
    assert!(protocol.decrypt_with_kek(&ciphertext, &wrong_kek).is_err());

    // Authentication must also fail after modifying the ciphertext body.
    *ciphertext.last_mut().unwrap() ^= 0x80;
    assert!(protocol.decrypt_with_kek(&ciphertext, &kek).is_err());
}
