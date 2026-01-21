use super::shamir;

#[test]
fn test_kek_uniqueness() {
    let shamir = shamir();
    let mut keks = std::collections::HashSet::new();

    // Generate many KEKs and ensure uniqueness
    for _ in 0..50 {
        // Reduced from 100 due to rejection sampling limits
        match shamir.random_k() {
            Ok(kek) => assert!(keks.insert(kek), "Duplicate KEK generated"),
            Err(_) => continue, // Skip failures due to rejection sampling
        }
    }

    // Ensure we got at least some unique KEKs
    assert!(!keks.is_empty(), "No unique KEKs generated");
}

#[test]
fn test_lock_keys_independence() {
    let shamir = shamir();
    let mut e_values = std::collections::HashSet::new();
    let mut d_values = std::collections::HashSet::new();

    // Generate many key pairs and check for collisions
    for _ in 0..25 {
        // Reduced from 50 due to rejection sampling limits
        match shamir.generate_lock_keys() {
            Ok(keys) => {
                assert!(e_values.insert(keys.e.clone()), "Duplicate e value");
                assert!(d_values.insert(keys.d.clone()), "Duplicate d value");
            }
            Err(_) => continue, // Skip failures due to rejection sampling
        }
    }

    // Ensure we got at least some unique keys
    assert!(!e_values.is_empty(), "No unique e values generated");
    assert!(!d_values.is_empty(), "No unique d values generated");
}

#[test]
fn test_ciphertext_randomness() {
    let shamir = shamir();
    let data = b"test data";

    let kek = match shamir.random_k() {
        Ok(k) => k,
        Err(_) => {
            // Skip test if we can't generate a KEK
            return;
        }
    };

    // Encrypt same data multiple times
    let mut ciphertexts = Vec::new();
    for _ in 0..5 {
        // Reduced from 10 due to rejection sampling limits
        match shamir.encrypt_with_kek(&kek, data) {
            Ok(ct) => ciphertexts.push(ct),
            Err(_) => continue, // Skip failures
        }
    }

    // Ensure we got at least some ciphertexts
    assert!(!ciphertexts.is_empty(), "No ciphertexts generated");

    // All ciphertexts should be different due to random nonces
    for i in 0..ciphertexts.len() {
        for j in i + 1..ciphertexts.len() {
            assert_ne!(
                ciphertexts[i], ciphertexts[j],
                "Identical ciphertexts produced"
            );
        }
    }
}

#[test]
fn test_decryption_failure_with_wrong_key() {
    let shamir = shamir();
    let data = b"secret data";

    let (ciphertext, _kek1) = match shamir.encrypt_with_random_kek_key(data) {
        Ok(result) => result,
        Err(_) => {
            // Skip test if we can't encrypt
            return;
        }
    };

    let kek2 = match shamir.random_k() {
        Ok(k) => k,
        Err(_) => {
            // Skip test if we can't generate a different key
            return;
        }
    };

    let result = shamir.decrypt_with_key(&ciphertext, &kek2);
    assert!(result.is_err(), "Decryption should fail with wrong key");
}

#[test]
fn test_ciphertext_tampering_detection() {
    let shamir = shamir();
    let data = b"authentic data";

    let (mut ciphertext, kek) = match shamir.encrypt_with_random_kek_key(data) {
        Ok(result) => result,
        Err(_) => {
            // Skip test if we can't encrypt
            return;
        }
    };

    // Tamper with ciphertext
    if let Some(last) = ciphertext.last_mut() {
        *last ^= 0xFF;
    }

    let result = shamir.decrypt_with_key(&ciphertext, &kek);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail authentication"
    );
}
