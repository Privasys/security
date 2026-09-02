# Privasys security

Public security analyses of the Privasys platform: formal models, reproductions of
published research against our implementations, and the harnesses that re-run them.
Everything here is meant to be checked, not believed: each folder carries exact
inputs, expected outputs and a CI job that regenerates them.

| Folder | Subject | Status |
|---|---|---|
| [`attested-tls-level3/`](attested-tls-level3/) | Level 3 binding of attestation evidence to the TLS connection for intra-handshake RA-TLS (CVE-2026-33697), re-run in the researchers' own ProVerif model with the Privasys binder | proven under compliant TLS 1.3, CI-verified |

After cloning:

    git submodule update --init

Licence: Apache-2.0 unless a folder states otherwise. See each folder's `NOTICE` for
attribution of derived work.
