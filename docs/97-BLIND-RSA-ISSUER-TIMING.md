# Blind-RSA issuer: timing side channels and RUSTSEC-2023-0071

Status: analysis of the token issuer's private-key path against the RSA Marvin
advisory, with the hardening it led to. Versions analysed are the ones locked on
2026-09-23: `blind-rsa-signatures` 0.17.2, `rsa` 0.10.0-rc.18, `crypto-bigint`
0.7.5, `rand` 0.10.1. The upstream state was checked the same day.

## Conclusion

Recovering the issuer key through the blind-signing path is not demonstrated,
and the mechanism the advisory describes does not reach it. Every
secret-dependent step of the private operation runs on `crypto-bigint`'s
constant-time arithmetic, the input is blinded with a fresh uniform factor on
every signature, and the CRT result is checked before it leaves the library.
The issuer now draws that factor from the operating system RNG and re-verifies
each signature itself before releasing it.

The residual risk is stated at the end: the constant-time property rests on
reading the source rather than measuring timings, and how many private-key
operations a requester can trigger is set by the deployer's issuance policy.

## The path

A client sends a blinded message `m` (256 bytes, any value below `n` it
likes). The issuer answers `m^d mod n`.

1. `IssuerSecretKey::blind_sign` (`crates/warrenguard-token/src/issuer.rs`)
   checks the length and calls `blind_sign_with_rng` with `rand::rngs::SysRng`.
2. `blind_rsa_signatures::SecretKey::blind_sign_with_rng` (`src/lib.rs`)
   decodes `m`, refuses `m >= n`, and calls
   `rsa::hazmat::rsa_decrypt_and_check(key, Some(rng), m)`.
3. `rsa_decrypt_and_check` (`rsa` `src/algorithms/rsa.rs`) runs
   `rsa_decrypt` (blinding, CRT exponentiation, unblinding), then recomputes
   `result^e mod n` and refuses the result unless it equals `m`.
4. The issuer's `release_if_valid` checks `sig < n` and `sig^e mod n == m`
   again before returning the signature.

## What the advisory covers

RUSTSEC-2023-0071 (CVE-2023-49092) reports that the `rsa` crate leaks
information about the private key through timing, originally because it
computed with the variable-time `num-bigint-dig`. The advisory lists no patched
version. Its current text says the move to `crypto-bigint` (RustCrypto/RSA#394)
did not close it, and tracks the remainder in three places, all open on
2026-09-23:

- #626: PKCS#1 v1.5 unpadding is not constant time.
- #680: implicit rejection for PKCS#1 v1.5 decryption.
- #702: blinding on the default PKCS#1 v1.5 and OAEP decryption paths, which
  run unblinded when no RNG is passed.

All three concern decryption with padding. The issuer path uses neither
padding nor the default decryption entry points.

## Findings

### The private operation is constant time in the secret values

With the precomputed CRT values present (always the case here, see "Key
loading"), `rsa_decrypt` computes:

- `c mod p` and `c mod q` with the `%` operator on `BoxedUint`, which is
  `BoxedUint::rem`, then `UintRef::div_rem` (`crypto-bigint`
  `src/uint/ref_type/div.rs`). That is the constant-time division: the divisor
  size it depends on is the precision of `p`, which is public. The
  variable-time variant, `div_rem_vartime`, is not on this path.
- `c^dP mod p` and `c^dQ mod q` with `BoxedMontyForm::pow`, which calls
  `pow_bounded_exp(exp, exp.bits_precision())`
  (`src/modular/boxed_monty_form/pow.rs`): a fixed-window exponentiation over
  the full precision of the exponent, with the window value selected by a
  constant-time scan of the whole table (`src/modular/pow.rs`). `dP` and `dQ`
  carry the precision of `p - 1` and `q - 1`, so their actual bit lengths do
  not show.
- The recombination (`m1 - m2`, `qInv * (m1 - m2)` in Montgomery form,
  `concatenating_mul` by `q`, `wrapping_add`) and the unblinding `mul_mod`
  (`concatenating_mul` then the constant-time `rem`) are fixed-time for a
  fixed precision.

The variable-time operations left on the path only touch public values: the
bounds checks on `m`, and `rsa_encrypt` (public exponent, applied to `r` and
to the signature, which the client receives anyway).

### Blinding is applied on every signature

`rsa_decrypt` blinds whenever it is given an RNG, and
`blind-rsa-signatures` always passes one. Each call draws `r` uniform in
`[0, n)` (`BoxedUint::try_random_mod_vartime`: rejection sampling with a
constant-time comparison, so the timing reveals only how many draws were
rejected), inverts it with the constant-time `invert_mod`, and exponentiates
`m * r^e`. The CRT arithmetic therefore runs on a value the client does not
know and cannot repeat: sending the same `m` twice exercises two unrelated
inputs.

Before this change the issuer called `blind_sign`, which uses the library's
`DefaultRng`, that is `rand::random()` on the thread-local `ThreadRng`: ChaCha12
in user space, seeded from the OS and reseeded every 64 KiB, with no fork
detection in `rand` 0.10.1 (`src/rngs/thread.rs`). The engine lock then
resolved its ChaCha core to `chacha20` 0.10.0, a yanked release whose SSE2
backend used an SSE4.1 intrinsic in exactly the `ThreadRng` code path
(RustCrypto/stream-ciphers#579), which is undefined behaviour on an x86 CPU
without SSE4.1 (CPUs with AVX2 take another backend). The lock now resolves
0.10.2, which fixes it, and the issuer now passes `SysRng`: one `getrandom`
read per draw, no user-space state, nothing shared across a fork. An RNG
failure refuses the signature.

### CRT faults cannot leak a factor

A CRT signature computed with a fault in one half, `s'`, gives
`gcd(s'^e - m, n) = p` to whoever receives it (Bellcore). `rsa_decrypt_and_check`
recomputes `s^e mod n` and refuses a mismatch before returning. The issuer
repeats that check in `release_if_valid`, so the property holds in the issuer
itself and does not depend on the library version it is built against.

### Key loading rejects inconsistent keys

`SecretKey::from_der` decodes through `RsaPrivateKey::from_components`, which
ignores the CRT exponents and coefficient stored in the DER and recomputes them
from `p`, `q` and `d` (`precompute`), after `validate` has checked `n = p * q`
and `d * e = 1 mod (p - 1)` and `mod (q - 1)`. A stored key with corrupted CRT
values cannot reach the signing path.

### There is no padding or decryption oracle on this path

The issuer applies no padding: PSS encoding happens on the client, before
blinding. It returns `m^d mod n` in full for any `m < n` the client submits.
Marvin and Bleichenbacher recover a plaintext the attacker does not see, from
the timing of a padding check on it. Here the requester receives the whole
result, so there is no hidden plaintext and no padding check to time. Timing
could only matter if it revealed the key, which the two sections above
address.

The same fact fixes a usage rule: a blind-RSA issuer key is a raw RSA
private-key oracle, so it must never serve any other purpose. Any RSA
ciphertext encrypted to it, or any other signature scheme using it, can be
opened or forged by submitting the value as a blinded request.

### The issuer's own code branches only on public data

`blind_sign` checks the request length, the library refuses `m >= n`, every
library error maps to the single value-free `TokenError::BlindOperation`, and
`release_if_valid` compares the public request with the public signature
exponentiated by the public exponent.

### Variable-time code on secrets, outside the request path

`precompute` and `validate` divide by `p - 1` and `q - 1` with `rem_vartime`.
They run once per key load, on the issuer's own schedule, so a client cannot
repeat or time them.

## Upstream releases

Checked on crates.io and in RustCrypto/RSA on 2026-09-23:

- `rsa`: the newest release is 0.10.0-rc.18 (2026-04-27), the locked version.
  0.10.0 final is not released. Master has since added an RSADoS note, the
  `signature` v3 bump and a regression test for CVE-2026-21895 (a panic on a
  prime equal to 1 at key load, whose fix rc.18 already carries). None of this
  touches the private operation.
- `blind-rsa-signatures`: the newest release is 0.17.2, the locked version.
- `crypto-bigint`: 0.7.5 is the newest release; 0.7.0 to 0.7.4 are yanked
  (0.7.4 for a Karatsuba carry bug).

No release changes the advisory's status, so the versions stay as they are.

An upgrade of `rsa` or `crypto-primes` has a hazard of its own for a deployer
that derives issuer keys deterministically, by feeding a seeded RNG to
`IssuerSecretKey::generate`. A release that changes key generation changes
every derived key, which invalidates every credential already issued. Such a
deployer needs a frozen seed-to-key-id vector before an upgrade lands.

## Residual risk

- The constant-time claims come from reading the source of the locked
  versions. No timing measurement (dudect-style) or review of the generated
  assembly was done, and a compiler can turn branch-free source into branches.
  The protection rests on `crypto-bigint`'s constant-time discipline, with
  blinding as a second, independent layer.
- This crate does not bound how many signatures a requester obtains; the
  deployer's issuance policy does. An issuer that signs again any request it
  has already answered (to let a client recover lost credentials, for
  instance) lets one requester drive an unbounded number of private-key
  operations on inputs of its choice, which is the measurement setting a
  timing attack needs. Blinding makes those repetitions useless for averaging
  a fixed internal value; serving the stored signatures, or rate-limiting
  repeats per requester, bounds the exposure outright.

## Tests that pin these properties

In `crates/warrenguard-token`:

- `issuer::tests::every_signature_draws_a_fresh_modulus_sized_blinding_factor`:
  each signature consumes at least a modulus of randomness from the RNG the
  issuer passes, and the output stays identical.
- `issuer::tests::a_blind_signature_that_does_not_verify_is_never_released`:
  the release gate refuses a corrupted signature.
- `issuer::tests::a_non_canonical_blind_signature_is_never_released`: the gate
  refuses `sig + n`, which passes the exponent check on its own.
- `tests/privacy_pass.rs` `blind_signature_over_a_fixed_request_is_frozen`: a
  known-answer blind signature under a fixed DER key, captured before the RNG
  and gate changes, which are therefore byte-identical on the wire.

## Advisory handling

RUSTSEC-2023-0071 stays ignored in `deny.toml` and `.cargo/audit.toml`, with a
justification pointing here, and the workspace pins `rsa` to exactly the
analysed release. Revisit it when an `rsa` release is marked patched, when
either crate is upgraded, or if the engine ever adds RSA decryption with
padding.
