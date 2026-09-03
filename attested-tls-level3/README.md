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
| `G-post-handshake-exporter` | post-handshake, exporter | as upstream, **all queries unchanged** | true | true | **true** |
| `H-post-handshake-exporter-compliant-tls` | post-handshake, exporter | as E | true | true | **true** |

In every model the reachability sanity queries stay false, so a run in which both
endpoints accept the same evidence exists and the proofs are not vacuous. Runtimes: 30
seconds to 9 minutes per model on one core.

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
- **Post-handshake, exporter binder** (G, H). The certificate carries the leaf key and
  the chain and no evidence (`CRT(pubEK, ID_S, server_cert)`, `CH(cr, offer)` without an
  attestation nonce). After client Finished the client sends a fresh context, the server
  answers with a quote, any number of times on one connection, and the client accepts it
  only if `rdata = (context, hctx, pubEK)` with `hctx` its own
  `HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""), "exporter", Hash(context))`
  (RFC 8446 section 7.5, the shape of RFC 9261). G adds one reachability query, described
  below; the authors' queries are untouched. H adds the four guards of D.

## Post-handshake attestation in the same model

The authors recommend post-handshake attestation with an exporter-derived binder as the
way to Level 3. Models G and H put that design under the same queries, in the same two
worlds, so that both designs are compared on one metric.

| Model | TLS in the model | G3 | Both endpoints share the application key and the attacker holds it |
|---|---|---|---|
| `B-privasys-binder` (intra-handshake) | weak DH, bad element, weak hash, all leaks | false | **reachable** |
| `D-privasys-binder-compliant-tls` (intra-handshake) | compliant TLS 1.3, all leaks | true | unreachable |
| `G-post-handshake-exporter` | weak DH, bad element, weak hash, all leaks | true | **reachable** |
| `H-post-handshake-exporter-compliant-tls` | compliant TLS 1.3, all leaks | true | unreachable |

The last column is the one query added in G and H:

    query ev:bitstring,kc:ae_key;
      event(ClientStateEvKc(ev,kc)) && event(ServerStateEvKc(ev,kc)) && attacker(kc).

Two things follow.

- The exporter binder reaches Level 3 with no assumption about the TLS stack. The
  exporter and the application key are siblings, both derived from the Master Secret and
  the transcript through server Finished, so equal exporters force equal application
  keys in any symbolic model. Intra-handshake binders fail G3 only because the
  application key also depends on Certificate, CertificateVerify and Finished, which do
  not exist when the quote is minted. A transcript collision cannot separate the two
  designs: a collision that equalised two exporters would equalise the two application
  keys by the same collision, and in this model the negotiated hash enters only
  CertificateVerify in any case.
- In the world where G3 fails for intra-handshake binders, G3 holds for the
  post-handshake binder while the attacker holds the application key: the trace
  negotiates `WeakDH` with `BadElement`, the attacker computes every secret and relays
  the handshake verbatim, and the quote binds correctly to a key three parties hold. G1
  to G3 are correlation goals. They say that the two endpoints derived the same key, not
  that nobody else has it. With compliant TLS 1.3 endpoints neither design leaves that
  trace, and both hold Level 3.

The B and D results in the last column come from local re-runs of those two models with
the same query appended; the published B and D patches are unchanged.

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
CA-signed certificate, no PSK resumption, no 0-RTT, and, apart from the attestation
exchange of G and H, no post-handshake messages. G and H omit the CertificateVerify and
Finished of an RFC 9261 authenticator, which add checks on the client side and cannot
weaken the binding; their attestation exchange runs on the public channel like every
handshake message in this model. "Compliant TLS 1.3" is four guards on the group, the
key share and the hash. The result concerns the three bound designs, the authors'
proposal, the Privasys intra-handshake binder and the post-handshake exporter binder;
the paper's relay traces on the seven unbound mechanisms exist in the model, under its
premise that the enclave's private key has already been extracted.

## Licence and credit

Apache-2.0, as the upstream artifacts. See `NOTICE`. The model, the queries and the
attack traces are the authors' work; this folder adds a few guarded lines and the
reproduction harness.
