# shamir-3-pass

Typed Rust primitives for the Shamir three-pass commutative encryption protocol, with native and `wasm32` support.

Version 0.6 uses a reviewed built-in group, checked group elements, and opaque lock-key pairs. It can deterministically derive independent lock-key pairs from one deployment root secret, which keeps backend configuration small.

## Installation

MSRV: Rust 1.85+

```toml
[dependencies]
shamir-3-pass = "0.6"
```

AEAD helpers are available behind a feature:

```toml
[dependencies]
shamir-3-pass = { version = "0.6", features = ["aead"] }
```

## Quickstart

```rust
use shamir_3_pass::Shamir3Pass;

// Shared public protocol parameters. Both parties must use the same group.
let protocol = Shamir3Pass::default();

// Server: create the durable lock pair. Persist or deterministically derive this pair.
let server = protocol.generate_lock_key_pair().unwrap();

// Client: create a one-time lock and parse the KEK as a checked group element.
let client = protocol.generate_lock_key_pair().unwrap();
let value = protocol.element_from_bytes(&123_456u64.to_be_bytes()).unwrap();

// Locking step: KEK -> KEK_c -> KEK_cs -> KEK_s (store `ciphertext` + `kek_s` on the server).
let client_locked = client.add_lock(&protocol, &value);            // KEK -> KEK_c
let double_locked = server.add_lock(&protocol, &client_locked);    // KEK_c -> KEK_cs
let server_locked = client.remove_lock(&protocol, &double_locked); // KEK_cs -> KEK_s

// Unlock step: KEK_s -> KEK_st -> KEK_t -> KEK (recovered).
let temporary = protocol.generate_lock_key_pair().unwrap(); // fresh temporary lock
let double_locked = temporary.add_lock(&protocol, &server_locked); // KEK_s -> KEK_st
let client_locked = server.remove_lock(&protocol, &double_locked); // KEK_st -> KEK_t
let recovered = temporary.remove_lock(&protocol, &client_locked);  // KEK_t -> KEK

assert!(recovered == value);
```

## Protocol overview

Shamir 3-pass uses commutative exponentiation over a shared public modulus `p`:

- Add a lock: `x' = x^e mod p`
- Remove your lock: `x = (x')^d mod p`, where `e*d ≡ 1 (mod p-1)`
- Locks commute: `(x^e_c)^e_s = (x^e_s)^e_c`

## Derive a backend lock from one root secret

Load one random 32-byte deployment secret from your secret manager and derive the durable server lock:

```rust
use shamir_3_pass::Shamir3Pass;

let root_secret: [u8; 32] = load_root_secret();
let protocol = Shamir3Pass::default();

let server_lock = protocol
    .derive_lock_key_pair(&root_secret, b"server-lock/v1")
    .unwrap();
```

The context is a stable public label. The same root and context reproduce the same pair; changing either rotates it. Keep the root secret random and store it in a secrets manager.

`LockKeyPair` does not implement `Clone` or `Debug`, and its exponents are private. `export_secret()` and `import_lock_key_pair()` provide an explicit persistence boundary when derived keys are unsuitable.

## Parameters and validation

`Shamir3Pass::default()` uses the 1024-bit MODP group from RFC 2409. `ModpGroup::Rfc2409Group1` provides an explicit 768-bit lower-security option for latency-sensitive applications, while `ModpGroup::Rfc3526Group14` selects the stronger 2048-bit group. `from_safe_prime` and `from_safe_prime_b64u` accept caller-selected safe primes of at least 256 bits after probabilistic primality checks of `p` and `(p - 1) / 2`. The caller is responsible for choosing a custom modulus size appropriate to its security and performance requirements.

External protocol values must enter through `element_from_bytes` or `element_from_b64u`. These constructors reject values outside `[2, p - 2]`. Lock application accepts only a checked `GroupElement` and an opaque key pair, preventing raw exponent mixups in normal API use.

## Optional AEAD helpers

With the `aead` feature, `encrypt_with_random_kek` encrypts arbitrary bytes using ChaCha20-Poly1305 and a fresh group element as the KEK. `decrypt_with_kek` authenticates and decrypts the result. Applications that already own their data-encryption format can leave the feature disabled.

## WASM

Randomness uses `getrandom`; its JavaScript backend is enabled automatically for `wasm32`.

```sh
cargo build --target wasm32-unknown-unknown
```

The byte and base64url constructors keep JavaScript/Wasm wrappers thin. This crate does not prescribe a generated JavaScript binding layer.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --features aead
```

## Security

This crate has not received a professional audit. Its modular exponentiation uses `num-bigint`, which is variable-time. Deploy it only where local timing and cache side channels are outside the threat model, or place operations behind an isolation boundary appropriate to your system.

See [SECURITY.md](SECURITY.md) for the full security scope and vulnerability-reporting process.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
