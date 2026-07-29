use super::{element, shamir};

#[test]
fn each_generated_pair_adds_and_removes_its_lock() {
    let protocol = shamir();
    for value in 2..12 {
        let keys = protocol.generate_lock_key_pair().unwrap();
        let original = element(value);
        let locked = keys.add_lock(protocol, &original);
        assert!(keys.remove_lock(protocol, &locked) == original);
    }
}

#[test]
fn independently_added_locks_commute() {
    let protocol = shamir();
    let first = protocol.generate_lock_key_pair().unwrap();
    let second = protocol.generate_lock_key_pair().unwrap();
    let original = element(42);

    let first_then_second = second.add_lock(protocol, &first.add_lock(protocol, &original));
    let second_then_first = first.add_lock(protocol, &second.add_lock(protocol, &original));

    assert!(first_then_second == second_then_first);
}
