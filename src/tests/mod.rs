use std::sync::OnceLock;

fn test_p_b64u() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| {
        crate::generate_shamir_p_b64u(crate::config::SHAMIR_MIN_PRIME_BITS)
            .expect("generate_shamir_p_b64u failed")
    })
    .as_str()
}

fn shamir() -> crate::Shamir3Pass {
    crate::Shamir3Pass::new(test_p_b64u()).expect("Shamir3Pass::new failed")
}

pub mod integration;

pub mod property_tests;

pub mod security_tests;

pub mod unit;
