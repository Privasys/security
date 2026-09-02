# Level 3 binding for intra-handshake attested TLS

A reproducible ProVerif result on the model published with
[Intra-handshake.fail (CVE-2026-33697)](https://github.com/muhammad-usama-sardar/intra-handshake.fail)
by Sardar, Dubeyko and Jacquet, whose headline claim is:

> "It may not be possible to achieve level 3 binding in intra-handshake attestation
> alone without additional assumptions."

The additional assumption is that TLS 1.3 is TLS 1.3. With compliant TLS 1.3 endpoints
in the model (strong (EC)DHE groups, key-share validation, SHA-2 cipher suites, as RFC
8446 mandates), ProVerif **proves Level 3** for the authors' own proposed binder and for
the binder shipped in Privasys RA-TLS, using the authors' G3 query **unchanged**, with
every key-leak process of the model (ephemeral key, long-term key, attestation key)
still running.

[Nathanael Ritz made the underlying observation first](https://lists.confidentialcomputing.io/g/attestation/topic/120068492?msg=326#msg326)
on the CCC Attestation SIG list on 1 July 2026: the relay queries do not carry the
standard cryptographic assumptions that every other query in the same model carries.

## Results

ProVerif 2.05, the version used for the published artifacts. "true" is a proof that no
attack trace exists in the symbolic model. "false" comes with a reconstructed attack
trace in the log.

| Model | Binder | TLS in the model | G1 (g^xy) | G2 (handshake key) | G3 (application key) |
|---|---|---|---|---|---|
| upstream `proposal/` | authors' | may negotiate weak DH, bad element, weak hash | true | true | **false** |
| `B-privasys-binder` | Privasys | as upstream | true | true | **false**, same trace |
| `A-proposal-g3-excl` | authors' | as upstream, G3 query excludes weak DH / bad element / weak hash, key leaks allowed | true | true | **true** |
| `C-privasys-binder-g3-excl` | Privasys | as A | true | true | **true** |
| `E-proposal-compliant-tls` | authors' | compliant TLS 1.3 endpoints, **G3 query unchanged**, key leaks allowed | true | true | **true** |
| `D-privasys-binder-compliant-tls` | Privasys | as E | true | true | **true** |

In every model the reachability sanity queries stay false, so a run in which both
endpoints accept the same evidence exists and the proofs are not vacuous. Runtimes: 2 to
9 minutes per model on one core.

## What the published G3 trace needs

The authors' own `proposal/log.txt` ends its G3 query with a reconstructed trace in
which four things hold at once:

1. the server negotiates a **weak DH group** and the attacker sends a **bad element**
   (`DHE_13(WeakDH,BadElement)`), so the attacker knows g^xy, hence the Handshake
   Secret, hence the binder;
2. the server negotiates a **weak hash** and the attacker forges CertificateVerify over
   a **collision** (`sign(privEK,collision)`);
3. the leaf key **privEK** is leaked;
4. the long-term key **privLTK** is leaked.

Client and server then share one quote but different Certificate and CertificateVerify
messages, hence different application keys. Items 1 and 2 model Logjam (2015, downgrade
to breakable export-grade Diffie-Hellman groups) and SLOTH (2016, transcript forgery
through MD5 and SHA-1 collisions). Neither exists in TLS 1.3: RFC 8446 offers no weak
groups, requires key-share validation (sections 4.2.8.1 and 7.4), and has no cipher
suite below SHA-256. Every other agreement query in the published model (G-TLS2, G-C1,
G-C2) excludes exactly these conditions. Only the three relay queries G1, G2, G3 do not.

## What each model changes

Each `models/<name>/changes.patch` is a unified diff against the authors'
`proposal/tls-lib-simple.pvl`; every changed line carries the word `Privasys`.

- **Privasys binder** (B, C, D). `kdf_exp` derives
  `client_handshake_traffic_secret = Derive-Secret(hs, "c hs traffic", CH..SH)` and
  returns `HKDF-Expand-Label(that, "privasys-ratls-binder-v1", Hash(CH..SH))`, as
  computed by the [Privasys rustls](https://github.com/Privasys/rustls) and
  [Privasys Go](https://github.com/Privasys/go) forks at the Certificate-emit seam, and
  folded into the AK-signed quote as `rdata = (nonce, binder, pubEK)`, the symbolic
  form of `SHA-512(SHA-256(SPKI) || nonce || binder)`.
- **G3 with exclusions** (A, C). The G3 query gains the same right-hand side as the
  authors' G-C2 query, once with the cryptographic exclusions only and once with the
  key-leak exclusions added.
- **Compliant TLS 1.3** (D, E). Four guards: the client offers only `StrongDH` and
  `StrongHash`, the server accepts only those, and both sides reject `BadElement` as a
  key share. The `SendBadElement`, `LEK`, `LAK` and `LLTK` processes still run, and all
  queries, including G3, are the authors' verbatim.

## Reproduce

    git submodule update --init
    ./run.sh proverif                                  # all models
    ./run.sh proverif D-privasys-binder-compliant-tls  # one model

`run.sh` applies each patch to a copy of the authors' pinned `proposal/` folder, runs
ProVerif and compares the relay-query summary with `expected.txt`. ProVerif 2.05 builds
from [its source tarball](https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz)
with an OCaml compiler. The GitHub Actions workflow does the same, one job per model.

## Interpretation

Inside the handshake the quote commits to the Handshake Secret and the transcript through
ServerHello. The application key derives from that same Handshake Secret and from a
transcript whose integrity the Finished MAC guarantees, with a key derived from the same
Handshake Secret. The commitment to the application key is therefore transitive, and
breaking it means holding the Handshake Secret without being an endpoint or forging the
authenticated transcript, which in TLS 1.3 needs cryptography the protocol does not
offer. Level 2 and Level 3 differ in what the quote commits to directly. Against a
compliant TLS 1.3 stack they do not differ in what an attacker can do.

## The IETF draft of 1 September 2026

[draft-intra-handshake-fail-18](https://www.ietf.org/archive/id/draft-intra-handshake-fail-18.html)
restates the same G1 to G3 table, raises the recommendation to "MUST urgently move to
post-handshake attestation", and announces further CVEs. It lists the Privasys
[rustls v0.8.1](https://github.com/Privasys/rustls/releases/tag/privasys-v0.8.1) and
[Go v0.5.1](https://github.com/Privasys/go/releases/tag/privasys-v0.5.1-go1.26.5)
releases under "vulnerable implementations", citing the release notes in which the CVE
was acknowledged. Those releases ship the binder modelled here. The three critical CVEs
published so far, all against Cocos AI, are verifier bugs rather than binding results:
an [expected reportData accepted when empty](https://github.com/ultravioletrs/cocos/security/advisories/GHSA-4r6g-mp48-j2rw),
an [expected value never copied into the quote policy](https://github.com/ultravioletrs/cocos/security/advisories/GHSA-4px3-wj2x-xx47),
and, in Cocos AI's post-handshake implementation,
[stale evidence accepted next to a fresh binder](https://github.com/ultravioletrs/cocos/security/advisories/GHSA-j7r9-wq7m-6hcp).

## Scope

A symbolic result in the authors' own model, with their abstractions: perfect
cryptography apart from the modelled weaknesses, a single self-signed leaf plus a
CA-signed certificate, no PSK resumption, no 0-RTT, no post-handshake messages.
"Compliant TLS 1.3" is four guards on the group, the key share and the hash. The result
concerns the two bound designs, the authors' proposal and ours; the paper's relay traces
on the seven unbound mechanisms exist in the model, under its premise that the enclave's
private key has already been extracted.

## Licence and credit

Apache-2.0, as the upstream artifacts. See `NOTICE`. The model, the queries and the
attack traces are the authors' work; this folder adds a few guarded lines and the
reproduction harness.
