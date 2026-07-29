use base64ct::{Base64UrlUnpadded, Encoding};
use num_bigint::BigUint;

use super::{element, shamir};
use crate::{decode_biguint_b64u, LockKeyPairBytes, ModpGroup, Shamir3Pass, Shamir3PassError};

#[test]
fn built_in_group_has_expected_identity_and_size() {
    let protocol = shamir();
    assert_eq!(protocol.group_id(), Some("rfc2409-group2"));
    assert_eq!(
        decode_biguint_b64u(&protocol.modulus_b64u())
            .unwrap()
            .bits(),
        1024
    );
}

#[test]
fn stronger_built_in_group_has_expected_identity_and_size() {
    let protocol = Shamir3Pass::from_group(ModpGroup::Rfc3526Group14);
    assert_eq!(protocol.group_id(), Some("rfc3526-group14"));
    assert_eq!(
        decode_biguint_b64u(&protocol.modulus_b64u())
            .unwrap()
            .bits(),
        2048
    );
}

#[test]
fn rfc_768_bit_group_has_expected_identity_and_size() {
    let protocol = Shamir3Pass::from_group(ModpGroup::Rfc2409Group1);
    assert_eq!(protocol.group_id(), Some("rfc2409-group1"));
    assert_eq!(
        decode_biguint_b64u(&protocol.modulus_b64u())
            .unwrap()
            .bits(),
        768
    );
}

#[test]
fn built_in_group_moduli_are_safe_primes() {
    for group in [
        ModpGroup::Rfc2409Group1,
        ModpGroup::Rfc2409Group2,
        ModpGroup::Rfc3526Group14,
    ] {
        let protocol = Shamir3Pass::from_group(group);
        let modulus = decode_biguint_b64u(&protocol.modulus_b64u()).unwrap();
        assert!(crate::utils::is_safe_prime(&modulus).unwrap());
    }
}

#[test]
fn rejects_custom_modulus_below_256_bits() {
    assert!(matches!(
        Shamir3Pass::from_safe_prime(BigUint::from(65_537u32)),
        Err(Shamir3PassError::PrimeTooSmall { min_bits: 256, .. })
    ));
}

#[test]
fn rejects_values_outside_the_checked_element_range() {
    let protocol = shamir();
    assert!(protocol.element_from_bytes(&[0]).is_err());
    assert!(protocol.element_from_bytes(&[1]).is_err());

    let modulus = decode_biguint_b64u(&protocol.modulus_b64u()).unwrap();
    assert!(protocol.element_from_bytes(&modulus.to_bytes_be()).is_err());
}

#[test]
fn exported_pair_round_trips_through_checked_import() {
    let protocol = shamir();
    let original = protocol.generate_lock_key_pair().unwrap();
    let encoded = original.export_secret();
    let imported = protocol.import_lock_key_pair(&encoded).unwrap();
    let value = element(9_999);

    assert!(imported.add_lock(protocol, &value) == original.add_lock(protocol, &value));
}

#[test]
fn deterministic_derivation_is_stable_and_context_separated() {
    let protocol = Shamir3Pass::default();
    let root = [0x42; 32];
    let first = protocol
        .derive_lock_key_pair(&root, b"example/server-lock/v1")
        .unwrap()
        .export_secret();
    let repeated = protocol
        .derive_lock_key_pair(&root, b"example/server-lock/v1")
        .unwrap()
        .export_secret();
    let other = protocol
        .derive_lock_key_pair(&root, b"example/another-lock/v1")
        .unwrap()
        .export_secret();

    assert_eq!(first.add_exponent(), repeated.add_exponent());
    assert_eq!(first.remove_exponent(), repeated.remove_exponent());
    assert_ne!(first.add_exponent(), other.add_exponent());
    assert!(protocol.derive_lock_key_pair(&root, b"").is_err());
}

#[test]
fn deterministic_derived_pair_has_a_fixed_interoperability_vector() {
    let protocol = Shamir3Pass::from_group(ModpGroup::Rfc3526Group14);
    let encoded = protocol
        .derive_lock_key_pair(&[0x42; 32], b"test/server/v1")
        .unwrap()
        .export_secret();

    assert_eq!(
        Base64UrlUnpadded::encode_string(encoded.add_exponent()),
        "b2opxb9fweO-3KQBQXdFQoNadpahZ8Winnjplo_mqsSWJijhZq3vY2Hq0xWhekxubFiNCvCJkpel_iN3ED2SpwAR3T9CoSjO7xjaTmZO8jvv1tZgSs_L__zuTEtZxuHKcik6cZ4WTnjSRsA2fU6EbutfwsUOCQRV8HrUvGrbzlR6Y-B3Bv9-ejXd2dswgqXJhGstsKpOPhadLreTKft20JtnrEnQ1CohhR7SXy0tb2u_4BYp95acAne5exJWBZP4qcepB7t8J8VvYvJGWaU28518kg604SVNSXPTuamIilrVtOwykTpahpaKpsFazP0_v6wc7lwnG4YZI_XZoApEQw"
    );
    assert_eq!(
        Base64UrlUnpadded::encode_string(encoded.remove_exponent()),
        "IO_DgEfX7kMkn_FRTcwtjoaK6RnpyvqcMi5FeZhqj9f02vv_K5_f9s6wD72BLNar8vd0zXUsrILfCDJiaaPznqERClfygZRf6OeeK4y6WZA3mF3zVoZljSJkY2rf51ET3xGC8NJtAbtVEX1gTwrwe_5DQPQiZItgfWvIwJCRzXI5y2rybqHTAMvJlvV6nTJYu90CX3ypGH3E2mDWsASb6WbJmXt8bn-y3CqVIh80nU5pA1wfGWi_md53tKTv8Ia0kVIYlCkIA28R_3naqZdkFzxYMTD-IJBd5bjJBNqZRlOdTCPvPPdtvYI46zLAIdSxG9OFsgbIow6SWJs55ritKQ"
    );
}

#[test]
fn import_rejects_empty_exponents() {
    let protocol = shamir();
    let encoded = LockKeyPairBytes::new(Vec::new(), Vec::new());
    assert!(protocol.import_lock_key_pair(&encoded).is_err());
}
