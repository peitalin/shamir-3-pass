# Security Policy

## Supported versions

Security fixes are provided on a best-effort basis for the latest released version and the `main` branch.

## Reporting a vulnerability

Do not open a public GitHub issue for a potential vulnerability. Report it privately to `n6378056@gmail.com`.

Include the affected version, impact, and reproduction steps.

## Cryptography disclaimer

This crate:

- has not received a professional audit;
- uses variable-time `num-bigint` operations;
- provides a fixed RFC 3526 group and validates custom safe primes probabilistically.

## Disclosure process

Maintainers aim to acknowledge reports promptly, coordinate disclosure with the reporter, and publish a release or advisory when a fix is available.
