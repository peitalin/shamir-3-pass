use super::{element, shamir};

#[test]
fn full_lock_and_unlock_flow_recovers_the_value() {
    let protocol = shamir();

    // Server generates its durable lock pair.
    let server = protocol.generate_lock_key_pair().unwrap();

    // === LOCK ===

    // Client generates a temporary lock pair.
    let locking = protocol.generate_lock_key_pair().unwrap();
    let original = element(123_456_789);

    // Client adds its temporary lock: KEK -> KEK_c.
    let client_locked = locking.add_lock(protocol, &original);

    // Server adds its durable lock: KEK_c -> KEK_cs.
    let double_locked = server.add_lock(protocol, &client_locked);

    // Client removes its temporary lock: KEK_cs -> KEK_s.
    let server_locked = locking.remove_lock(protocol, &double_locked);

    // === UNLOCK ===

    // Client generates a fresh temporary lock pair for this operation.
    let unlocking = protocol.generate_lock_key_pair().unwrap();

    // Client adds its temporary lock: KEK_s -> KEK_st.
    let double_locked = unlocking.add_lock(protocol, &server_locked);

    // Server removes its durable lock: KEK_st -> KEK_t.
    let client_locked = server.remove_lock(protocol, &double_locked);

    // Client removes its temporary lock: KEK_t -> KEK.
    let recovered = unlocking.remove_lock(protocol, &client_locked);

    // The original group element is recovered after both locks are removed.
    assert!(recovered == original);
}

#[cfg(feature = "aead")]
#[test]
fn optional_aead_round_trip() {
    let protocol = shamir();
    let plaintext = b"secret payload";
    let (ciphertext, kek) = protocol.encrypt_with_random_kek(plaintext).unwrap();

    // Ciphertext contains the 12-byte nonce and 16-byte authentication tag.
    assert_eq!(ciphertext.len(), plaintext.len() + 12 + 16);
    assert_eq!(
        protocol.decrypt_with_kek(&ciphertext, &kek).unwrap(),
        plaintext
    );
}
