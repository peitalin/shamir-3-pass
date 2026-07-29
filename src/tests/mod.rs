use std::sync::OnceLock;

use crate::{GroupElement, Shamir3Pass};

fn shamir() -> &'static Shamir3Pass {
    static SHAMIR: OnceLock<Shamir3Pass> = OnceLock::new();
    SHAMIR.get_or_init(Shamir3Pass::default)
}

fn element(value: u64) -> GroupElement {
    shamir()
        .element_from_bytes(&value.to_be_bytes())
        .expect("test value must be a group element")
}

pub mod integration;
pub mod property_tests;
pub mod security_tests;
pub mod unit;
