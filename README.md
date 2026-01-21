# shamir-3-pass

Rust implementation of the Shamir 3-pass (commutative encryption) protocol, intended for use in native and `wasm32` builds.

## Installation

Add as a dependency:
```toml
[dependencies]
shamir-3-pass = "0.5"
```


## Usage

```rust
use shamir_3_pass::{generate_shamir_p_b64u, Shamir3Pass};

// Generate `p` once, persist it, and share it with the other party.
// `256` is the minimum; consider using a larger modulus (e.g. 2048) for additional margin.
let p_b64u = generate_shamir_p_b64u(256).unwrap();
let shamir = Shamir3Pass::new(p_b64u.as_str()).unwrap();

// Server generates long-lived lock keys (e_s, d_s)
let server = shamir.generate_lock_keys().unwrap();

// Client encrypts some data under a random KEK
let (ciphertext, kek) = shamir.encrypt_with_random_kek_key(b"secret").unwrap();

// Client creates a one-time lock (e_c, d_c)
let client = shamir.generate_lock_keys().unwrap();

// Registration: KEK -> KEK_c -> KEK_cs -> KEK_s
let kek_c = shamir.add_lock(&kek, &client.e);
let kek_cs = shamir.add_lock(&kek_c, &server.e);
let kek_s = shamir.remove_lock(&kek_cs, &client.d);

// Login: KEK_s -> KEK_st -> KEK_t -> KEK (recovered)
let client_login = shamir.generate_lock_keys().unwrap();
let kek_st = shamir.add_lock(&kek_s, &client_login.e);
let kek_t = shamir.remove_lock(&kek_st, &server.d);
let kek_recovered = shamir.remove_lock(&kek_t, &client_login.d);

let plaintext = shamir.decrypt_with_key(&ciphertext, &kek_recovered).unwrap();
assert_eq!(plaintext, b"secret");
```

## Encoding for transport / storage

If you need to send lock exponents or KEKs across the network (or store them), encode them as base64url (unpadded):

```rust
use shamir_3_pass::{
    decode_biguint_b64u, encode_biguint_b64u, generate_shamir_p_b64u, Shamir3Pass,
};

let p_b64u = generate_shamir_p_b64u(256).unwrap();
let shamir = Shamir3Pass::new(p_b64u.as_str()).unwrap();
let keys = shamir.generate_lock_keys().unwrap();

let e_b64u = encode_biguint_b64u(&keys.e);
let e = decode_biguint_b64u(&e_b64u).unwrap();
assert_eq!(e, keys.e);
```

## WASM

- Randomness uses `getrandom`; the `js` backend is enabled automatically when building for `wasm32`.
- This library is Rust-first; it works in `wasm32` when used from Rust code.

Build for `wasm32`:

```sh
cargo build --target wasm32-unknown-unknown
```
