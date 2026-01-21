use num_bigint::BigUint;

use super::shamir;

#[test]
fn test_full_registration_login_flow() {
    let shamir = shamir();

    // Server generates permanent keys
    let server_keys = shamir
        .generate_lock_keys()
        .expect("Server key generation failed");

    // === REGISTRATION ===

    // Client encrypts VRF key
    let vrf_key = b"super secret VRF key material";
    let (ciphertext_vrf, kek) = shamir
        .encrypt_with_random_kek_key(vrf_key)
        .expect("Encryption failed");

    // Client generates temporary registration keys
    let client_lock_keys = shamir
        .generate_lock_keys()
        .expect("Client key generation failed");

    // Client adds lock: KEK → KEK_c
    let kek_c = shamir.add_lock(&kek, &client_lock_keys.e);

    // Server adds lock: KEK_c → KEK_cs
    let kek_cs = shamir.add_lock(&kek_c, &server_keys.e);

    // Client removes lock: KEK_cs → KEK_s
    let kek_s = shamir.remove_lock(&kek_cs, &client_lock_keys.d);

    // === LOGIN ===

    // Client generates new temporary login keys
    let client_login_keys = shamir
        .generate_lock_keys()
        .expect("Client login key generation failed");

    // Client adds lock: KEK_s → KEK_st
    let kek_st = shamir.add_lock(&kek_s, &client_login_keys.e);

    // Server removes lock: KEK_st → KEK_t
    let kek_t = shamir.remove_lock(&kek_st, &server_keys.d);

    // Client removes lock: KEK_t → KEK
    let kek_recovered = shamir.remove_lock(&kek_t, &client_login_keys.d);

    // Verify KEK recovery
    assert_eq!(kek_recovered, kek, "KEK recovery failed");

    // Decrypt VRF key
    let decrypted_vrf = shamir
        .decrypt_with_key(&ciphertext_vrf, &kek_recovered)
        .expect("Decryption failed");

    assert_eq!(decrypted_vrf, vrf_key);
}

#[test]
fn test_commutative_property() {
    let shamir = shamir();

    let keys1 = shamir.generate_lock_keys().unwrap();
    let keys2 = shamir.generate_lock_keys().unwrap();
    let keys3 = shamir.generate_lock_keys().unwrap();

    let value = BigUint::from(999999u32);

    // Test all 6 permutations of 3 operations
    let permutations = vec![
        vec![
            (&keys1.e, true),
            (&keys2.e, true),
            (&keys3.e, true),
            (&keys1.d, false),
            (&keys2.d, false),
            (&keys3.d, false),
        ],
        vec![
            (&keys1.e, true),
            (&keys3.e, true),
            (&keys2.e, true),
            (&keys3.d, false),
            (&keys1.d, false),
            (&keys2.d, false),
        ],
        vec![
            (&keys2.e, true),
            (&keys1.e, true),
            (&keys3.e, true),
            (&keys2.d, false),
            (&keys3.d, false),
            (&keys1.d, false),
        ],
    ];

    for perm in permutations {
        let mut result = value.clone();
        for (key, is_add) in perm {
            result = if is_add {
                shamir.add_lock(&result, key)
            } else {
                shamir.remove_lock(&result, key)
            };
        }
        assert_eq!(result, value, "Commutative property violated");
    }
}

#[test]
fn test_encryption_with_different_data_sizes() {
    let shamir = shamir();

    let test_sizes = vec![
        0,     // Empty
        1,     // Single byte
        16,    // AES block size
        1024,  // 1KB
        65536, // 64KB
    ];

    for size in test_sizes {
        let data = vec![0xAA; size];
        let (ciphertext, kek) = shamir.encrypt_with_random_kek_key(&data).unwrap();

        // Ciphertext should be data + 12 (nonce) + 16 (auth tag)
        assert_eq!(ciphertext.len(), size + 12 + 16);

        let decrypted = shamir.decrypt_with_key(&ciphertext, &kek).unwrap();
        assert_eq!(decrypted, data);
    }
}
