# shamir-3-pass

Rust implementation of the Shamir 3-pass (commutative encryption) protocol, intended for use in native and `wasm32` builds.

## Protocol overview

Shamir 3-pass is a *commutative lock* on the KEK:

- Adding a lock is exponentiation: `kek_locked = kek^e mod p`.
- Locks commute, so the order doesn’t matter: `(kek^e_c)^e_s = (kek^e_s)^e_c`.
- Each lock has an inverse exponent `d` so you can remove your own lock: `(kek^e)^d = kek`.

- **Registration**: `kek → kek_c → kek_cs → kek_s`
  - Client adds its lock: `kek_c = kek^e_c mod p`
  - Server adds its lock: `kek_cs = kek_c^e_s mod p`
  - Client removes its lock: `kek_s = kek_cs^d_c mod p` (stored; still locked by server)
- **Login**: `kek_s → kek_st → kek_t → kek`
  - Client adds a fresh temporary lock: `kek_st = kek_s^e_t mod p`
  - Server removes its lock: `kek_t = kek_st^d_s mod p`
  - Client removes its temporary lock: `kek = kek_t^d_t mod p`

Because the locks commute, each side can add/remove only its own lock while never needing the other side's secret exponents.

## Installation

Add as a dependency:
```toml
[dependencies]
shamir-3-pass = "0.5"
```


## Usage

```rust
use shamir_3_pass::{generate_shamir_p_b64u, Shamir3Pass};

// Setup (shared): generate `p` once, persist it, and share it with the other party.
// `256` is the minimum; consider using a larger modulus (e.g. 2048) for additional margin.
let p_b64u = generate_shamir_p_b64u(256).unwrap();
let shamir = Shamir3Pass::new(p_b64u.as_str()).unwrap();

// Server: generate long-lived lock keys (e_s, d_s)
let server = shamir.generate_lock_keys().unwrap();

// Client: encrypt some data under a random KEK
let (ciphertext, kek) = shamir.encrypt_with_random_kek_key(b"secret").unwrap();

// Client: create a one-time lock (e_c, d_c)
let client = shamir.generate_lock_keys().unwrap();

// Locking step: KEK -> KEK_c -> KEK_cs -> KEK_s
// Client:
let kek_c = shamir.add_lock(&kek, &client.e);
// Server:
let kek_cs = shamir.add_lock(&kek_c, &server.e);
// Client:
let kek_s = shamir.remove_lock(&kek_cs, &client.d);

// Unlock step: KEK_s -> KEK_st -> KEK_t -> KEK (recovered)
// Client: create a fresh temporary lock (e_t, d_t)
let client_login = shamir.generate_lock_keys().unwrap();
// Client:
let kek_st = shamir.add_lock(&kek_s, &client_login.e);
// Server:
let kek_t = shamir.remove_lock(&kek_st, &server.d);
// Client:
let kek_recovered = shamir.remove_lock(&kek_t, &client_login.d);

// Client:
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
