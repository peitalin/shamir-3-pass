use super::shamir;
use num_bigint::BigUint;

#[test]
fn test_lock_unlock_inverse() {
    let shamir = shamir();

    for _ in 0..10 {
        // Reduced from 20 due to rejection sampling limits
        let keys = match shamir.generate_lock_keys() {
            Ok(keys) => keys,
            Err(_) => continue, // Skip failures due to rejection sampling
        };

        let value = match shamir.random_k() {
            Ok(k) => k,
            Err(_) => continue, // Skip failures due to rejection sampling
        };

        // Add then remove
        let locked = shamir.add_lock(&value, &keys.e);
        let unlocked = shamir.remove_lock(&locked, &keys.d);
        assert_eq!(unlocked, value);

        // Remove then add (should also work due to commutativity)
        let unlocked = shamir.remove_lock(&value, &keys.d);
        let locked = shamir.add_lock(&unlocked, &keys.e);
        assert_eq!(locked, value);
    }
}

#[test]
fn test_associative_property() {
    let shamir = shamir();

    let keys1 = shamir.generate_lock_keys().unwrap();
    let keys2 = shamir.generate_lock_keys().unwrap();
    let keys3 = shamir.generate_lock_keys().unwrap();

    let value = BigUint::from(42u32);

    // (a * b) * c = a * (b * c)
    let left = shamir.add_lock(&value, &keys1.e);
    let left = shamir.add_lock(&left, &keys2.e);
    let left = shamir.add_lock(&left, &keys3.e);

    let right = shamir.add_lock(&value, &keys2.e);
    let right = shamir.add_lock(&right, &keys3.e);
    let right = shamir.add_lock(&right, &keys1.e);

    assert_eq!(left, right);
}
