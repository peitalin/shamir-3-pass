# Security Policy

## Supported versions

Security fixes are provided on a best-effort basis for the latest released version and the `main` branch.

## Reporting a vulnerability

Do not open a public GitHub issue for a potential vulnerability. Report it privately to `dev@web3authn.org` or `n6378056@gmail.com` with the affected versions, impact, reproduction steps, and any suggested mitigation.

## Cryptographic scope

This crate has not received a professional audit.

Version 0.6 uses the RFC 3526 group 14 safe prime by default, validates custom safe primes probabilistically, checks external group elements, hides secret exponents behind typed key pairs, and zeroizes their persistent byte buffers on drop. HKDF-SHA256 provides deterministic root-secret derivation with explicit context separation.

The `num-bigint` operations used for modular exponentiation, inversion, primality testing, and integer conversion are variable-time. `Zeroizing<Vec<u8>>` limits retention of stored exponent bytes; transient `BigUint` allocations may leave copies in memory until their allocator storage is reused. The crate therefore does not claim resistance to local timing, cache, process-memory inspection, swap, crash-dump, or cold-boot attacks.

Safe deployment requires:

- a uniformly random 32-byte root secret stored in a secrets manager;
- unique, stable derivation contexts for every service, environment, role, and version;
- authenticated authorization around any endpoint applying a long-lived lock;
- rate limiting and operational isolation consistent with the side-channel threat model;
- protocol values parsed through the checked `GroupElement` constructors.

Applications facing hostile co-tenants, local attackers, or high-resolution timing observers should use a reviewed constant-time modular-arithmetic backend before relying on this crate.

## Disclosure process

Maintainers aim to acknowledge reports promptly, coordinate a fix and disclosure timeline with the reporter, and publish a release or advisory when a fix is ready.
