# The Privasys session relay in ProVerif

A formal model of the protocol that lets a browser reach an attested enclave through an
untrusted relay and a TLS-terminating gateway with the request and response bodies
confidential to the enclave: the enclave bootstrap, the WebAuthn challenge that binds the
attestation result to the session, the IdP-issued token, and the sealed session key. The
model follows the wire contract implemented by the browser SDK, the wallet, the identity
provider and the two enclave runtimes; every constant, hash input and key-derivation input
in the model is one the implementations compute.

## Assumptions

Two assumptions frame the model, and the result should be read with them.

- **Enclave-bound secrets are secure.** The keys an enclave generates and keeps, the TLS
  leaf and the session-relay identity key, do not leave it. The identity key lives in the
  Privasys vault and in the enclaves that host the app, all of them TEEs.
- **The Privasys identity provider is not adversarial.** It signs tokens honestly and it
  serves the SDK iframe honestly. The iframe runs on the identity-provider origin so that a
  user can connect on any website, and it holds the session key; the guarantee against
  the identity provider itself is organisational and auditable, not cryptographic. This
  assumption is the one we intend to weaken once the identity provider runs in an enclave.

Two results of other analyses are taken as given rather than re-modelled. RA-TLS is an
authenticated channel to the enclave whose digest the attestation names, the Level 3 result
of [`attested-tls-level3/`](../attested-tls-level3/). WebAuthn is a signature by the
hardware key over the relying-party identifier and the challenge.

## The protocol, as modelled

1. The SDK, an iframe on the identity-provider origin, draws an ephemeral P-256 key and
   shows a QR carrying a nonce and `sdk_pub`.
2. The wallet scans it, connects to the enclave over RA-TLS and verifies its attestation.
   The attestation names a measurement digest `q` and the TLS leaf key. It posts `sdk_pub`
   to the enclave, which draws `session_id`, derives
   `K = HKDF(ECDH(enc_priv, sdk_pub), salt = session_id)` against its identity key
   `enc_pub`, and returns `session_id` and `enc_pub` over the attested channel.
3. The wallet signs, with the hardware credential of the user, a WebAuthn assertion whose
   challenge is `SHA-256(label || nonce || sdk_pub || q || enc_pub || session_id)`.
4. The IdP verifies the assertion against the registered credential, recomputes the
   challenge from the inputs the wallet supplied, and issues a signed token carrying the
   user, the audience, `q`, `enc_pub`, `session_id` and `SHA-256(sdk_pub)`.
5. The SDK checks the token signature, that `SHA-256(sdk_pub)` is its own key, that `q` is
   the digest its policy pins, derives the same `K`, and seals requests to the enclave with
   AES-256-GCM under `K`, the session id as associated data.

The attacker is the network: the relay, the gateway, and every dishonest enclave, which
can obtain attestation for any key it likes under a measurement of its own but never under
the measurement an honest enclave runs. After the sessions, the IdP signing key and every
hardware credential leak to the attacker as well.

## Results

ProVerif 2.05, under a second. "true" is a proof that no attack trace exists in the
symbolic model. The two sanity queries are expected false: they show that the SDK does
accept and the enclave does open a sealed message, so the proofs are not vacuous.

| Property | Result |
|---|---|
| Secrecy: a payload the SDK seals in a session it accepted stays unknown to the attacker, including after the later leak of the IdP key and the credentials | **true** |
| Key agreement: whenever the SDK derives `K` for measurement `q`, identity `enc_pub`, session id and its own `sdk_pub`, an honest enclave running `q` derived the same `K` for the same session id and `sdk_pub` | **true** |
| Attestation agreement: whenever the SDK accepts a session for user `u`, the wallet of `u` verified that enclave and bound that `sdk_pub`, `enc_pub` and session id into the challenge it signed | **true** |

In words: with an honest IdP, the token the SDK accepts can only have come from a wallet
that verified the pinned measurement on the enclave that holds `enc_pub`, and the key the
SDK derives is shared with that enclave and nobody else. The relay, the gateway and any
enclave with a different measurement gain nothing, and neither does an attacker who later
obtains the IdP signing key or the hardware credential of the user. The binding challenge
does what the design says it does.

## Out of scope

- **Cross-device consent.** The wallet cannot tell which SDK instance showed the QR it
  scanned. A user who scans a QR displayed by an attacker binds the session of the
  attacker to their own credential. This is the known limit of every QR-initiated
  cross-device flow and is a matter of what the wallet shows the user, not of the
  cryptography; the model treats the QR as public and proves what holds regardless.
- **A dishonest wallet.** A wallet that skips verification and reports an `enc_pub` of its
  choosing defeats its own user only; the SDK still pins the measurement digest.
- **The voucher for silent rebinding, the sealed WebSocket streams, counters and the
  associated-data discipline.** Later models; the bootstrap and the binding are the
  load-bearing part and were modelled first.
- Everything symbolic models abstract: perfect primitives, no side channels, no key
  agreement details of P-256 beyond the Diffie-Hellman equation.

## Reproduce

    ./run.sh proverif205

`run.sh` copies `models/A-shipped/model.pv` to `work/A-shipped/`, runs ProVerif, extracts the
verification summary and compares it with `models/A-shipped/expected.txt`. The CI workflow
of this repository builds ProVerif 2.05 from source and runs the model on each push.

## Licence

Apache-2.0. The model is original work of Privasys.
