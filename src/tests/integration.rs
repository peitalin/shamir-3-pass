use super::{element, shamir};

#[test]
fn full_registration_and_rehydration_flow_recovers_the_value() {
    let protocol = shamir();
    let server = protocol.generate_lock_key_pair().unwrap();
    let registration = protocol.generate_lock_key_pair().unwrap();
    let original = element(123_456_789);

    let client_locked = registration.add_lock(protocol, &original);
    let double_locked = server.add_lock(protocol, &client_locked);
    let server_locked = registration.remove_lock(protocol, &double_locked);

    let rehydration = protocol.generate_lock_key_pair().unwrap();
    let double_locked = rehydration.add_lock(protocol, &server_locked);
    let client_locked = server.remove_lock(protocol, &double_locked);
    let recovered = rehydration.remove_lock(protocol, &client_locked);

    assert!(recovered == original);
}

#[cfg(feature = "aead")]
#[test]
fn optional_aead_round_trip() {
    let protocol = shamir();
    let plaintext = b"secret payload";
    let (ciphertext, kek) = protocol.encrypt_with_random_kek(plaintext).unwrap();

    assert_eq!(ciphertext.len(), plaintext.len() + 12 + 16);
    assert_eq!(
        protocol.decrypt_with_kek(&ciphertext, &kek).unwrap(),
        plaintext
    );
}
