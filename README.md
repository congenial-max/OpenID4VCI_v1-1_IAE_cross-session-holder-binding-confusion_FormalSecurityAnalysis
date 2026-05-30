# Tamarin Analysis — OpenID4VCI_v1.1 IAE Cross-Session Holder-Binding Confusion (A1)

A symbolic (Dolev–Yao) analysis in the [Tamarin Prover](https://tamarin-prover.github.io/) of a **holder-binding confusion attack** in the **Interactive Authorization Endpoint (IAE)** "presentation-during-issuance" flow of **OpenID for Verifiable Credential Issuance 1.1** (editor's draft `openid-4-verifiable-credential-issuance-1_1-01`).

In that flow the Credential Issuer acts as an OpenID4VP Verifier: to obtain a derived credential, a Wallet must first present an existing one. The new credential's **subject claims** come from the *presented* credential, while its **holder-binding key** comes from the *issuance key proof* — and the spec mandates no cryptographic link between the two. The model shows that, as written, this lets an adversary obtain a credential carrying an **honest victim's subject claims but bound to a key the adversary controls** — a usable impersonation credential — **without compromising any long-term key** (not the Issuer's, not the AS's, not the victim's holder key).

The repository contains a single source model with four build-time configurations: the protocol as written (attackable), one natural-but-insufficient fix, and two fixes that close the attack.

> **On the "A1" label.** "A1" is our internal identifier for this attack vector and the prefix used for every theory/lemma in the model (`OID4VCI_A1`, `a1_no_impersonation`, `a1_attack_witness`, …), so the artifacts line up with the write-up. It is **not** a severity rating and **not** a reference to any external (OWASP/CWE) catalogue.


## The attack in one paragraph

The adversary opens its own `auth_session` with the Credential Issuer `CI`, relays `CI`'s Issuer-signed presentation request (carrying `nonce_A`, audience `iar:CI`) to an honest victim, and consumes the victim's **genuine** Verifiable Presentation in the adversary's session. `CI`'s session-fixation check (`nonce ↔ auth_session`) passes, so `CI` mints an Access Token storing the victim's holder key and subject. The adversary then sends a Credential Request with a key proof under **its own** key; nothing requires that key to equal the presented holder key, so `CI` issues a credential carrying the **victim's** subject bound to the **adversary's** key. It is a binding failure, not an interception or a forgery — TLS confidentiality and signature unforgeability both hold throughout.

The four configurations are selected at build time with mutually exclusive `-D` flags on the **one** source file; there is no separate file per configuration. The `proofs/` directory is optional and holds the machine-checked proof outputs (produced with `--output`, see below).

## Requirements

- **Tamarin Prover 1.12.0** (the version the model was developed and checked against)
- **Maude 3.5.1**
- **GraphViz** (for rendering attack graphs in interactive mode)

Install per the official manual: <https://tamarin-prover.github.io/manual/book/002_installation.html>. Other 1.1x releases will likely work, but verdicts and proof sizes were confirmed only on 1.12.0 / Maude 3.5.1.

## Reproducing the results

Pass **exactly one** `-D` flag per run — the four configurations are mutually exclusive. Full terminal commands, runtimes and RAM usage are recorded at the end of each log file in this repository.

```sh
# Prove every lemma in a given configuration:
tamarin-prover --prove -DVULNERABLE   --auto-sources OID4VCI_A1_IAE_holder_binding.spthy
tamarin-prover --prove -DFIXED_NONCE  --auto-sources OID4VCI_A1_IAE_holder_binding.spthy
tamarin-prover --prove -DFIXED        --auto-sources OID4VCI_A1_IAE_holder_binding.spthy
tamarin-prover --prove -DFIXED_TXDATA --auto-sources OID4VCI_A1_IAE_holder_binding.spthy
```

Save the machine-checked proof to a file:

```sh
tamarin-prover --prove -DVULNERABLE --auto-sources \
  OID4VCI_A1_IAE_holder_binding.spthy --output=proofs/vulnerable.spthy
```


## Expected results

**Headline:** `a1_no_impersonation` (the same all-traces property in every configuration) is **falsified** under `VULNERABLE` and `FIXED_NONCE` (the attack exists) and **verified** under `FIXED` and `FIXED_TXDATA` (the attack is closed). Under `VULNERABLE`, `a1_attack_witness` additionally returns a concrete, reveal-free proof-of-concept trace.

| `-D` flag | Issuance-step mechanism | Cross-session confusion (A1) | `a1_no_impersonation` |
|---|---|---|---|
| `VULNERABLE` | none (spec as written) | reproducible | **falsified** (attack) |
| `FIXED_NONCE` | key proof must carry the `auth_session` nonce | still reproducible | **falsified** (attack) |
| `FIXED` | issuance key proof key = presented holder key (continuity) | closed | **verified** |
| `FIXED_TXDATA` | presenter commits `h(k_iss)` inside the KB-JWT; Issuer checks the proof key against it | closed (key separation OK) | **verified** |

Lemma-by-lemma:

| Lemma | Type | `VULNERABLE` | `FIXED_NONCE` | `FIXED` | `FIXED_TXDATA` |
|---|---|---|---|---|---|
| `ltkCI_secrecy` | all-traces | verified | verified | verified | verified |
| `skH_secrecy` | all-traces | verified | verified | verified | verified |
| `holderkey_unique` | all-traces | verified | verified | verified | verified |
| `exec_honest_iae_flow` | exists-trace | trace found | trace found | trace found | trace found |
| `a1_no_impersonation` | all-traces | **falsified** | **falsified** | verified | verified |
| `a1_attack_witness` | exists-trace | trace found | — | — | — |
| `a1_holder_continuity_vuln` | all-traces | **falsified** | — | — | — |
| `a1_holder_continuity_nonce` | all-traces | — | **falsified** | — | — |
| `a1_holder_continuity_fixed` | all-traces | — | — | verified | — |
| `a1_holder_authorization_txdata` | all-traces | — | — | — | verified |

**Legend.** For an *all-traces* lemma, "verified" means the property holds on every trace and "falsified" means Tamarin found a counterexample (i.e. the attack). For an *exists-trace* lemma, "trace found" means the described trace exists (`exec_honest_iae_flow` = the honest flow is executable; `a1_attack_witness` = the attack PoC exists). "—" means the lemma is not present in that configuration. All four configurations pass Tamarin's well-formedness checks.

## The four configurations

- **`VULNERABLE` — the spec as written.** No link is enforced between the presented holder key `k_pres` and the issuance key-proof key `k_proof`. The attack reproduces. `a1_holder_continuity_vuln` is falsified even *without any adversary key* — a credential can be bound to a *second honest holder's* key while the presentation was the victim's — which isolates the structural gap (the key proof binds only `(CI, pkH)`, never the session or the presenter).
- **`FIXED_NONCE` — natural fix that does not work (negative result).** The issuance key proof is required to carry the `auth_session` nonce. It still falsifies, because the nonce ships in the clear in the `require_interaction` response: any party freshly mints a key proof over **its own** key carrying that public nonce. Generally, no payload-level extension of the key proof helps, because the key proof is signed under the issuance key the adversary controls.
- **`FIXED` — holder-key continuity.** `CI` requires the issuance key proof to verify under, and the credential to be bound to, the **same** holder key that signed the accepted presentation's KB-JWT. In the impersonation trace this forces `pk(skH_Adv) = pk(skH_pres)`, impossible for distinct fresh keys, so `a1_no_impersonation` closes. Simplest fix; the issued key must equal the presented key.
- **`FIXED_TXDATA` — presenter-signed commitment.** The presenter commits to a thumbprint `h(k_iss)` of the intended issuance key **inside the KB-JWT it already signs** (carried via the OpenID4VP `transaction_data` mechanism); `CI` checks the proof key against that commitment. Closes the attack **and** permits `k_iss ≠ k_pres`, so a Wallet can bind each credential to a fresh key for unlinkability. The proof discharges the cuckoo branch via a KB-JWT-origin argument: only the genuine presenter can authorize an issuance key, and forging the commitment requires the victim's holder key.

## Lemma reference

Helper lemmas (`[reuse, use_induction]`):

- **`ltkCI_secrecy`** — the Credential Issuer's signing key stays secret unless explicitly revealed via `Reveal_CI_Ltk`.
- **`skH_secrecy`** — a victim holder's private key stays secret unless explicitly revealed via `Reveal_VictimHolderKey`.
- **`holderkey_unique`** — a holder public key originates from a single fresh generation (rules out accidental key collisions).

Sanity / executability:

- **`exec_honest_iae_flow`** (exists-trace) — the honest presentation-during-issuance flow runs to completion, with no Issuer-key reveal. Guards against an over-constrained model in which the security lemmas would hold vacuously.

Security properties:

- **`a1_no_impersonation`** (all-traces, the headline, stated identically in every configuration) — *no credential is ever issued bound to an adversary-controlled key while the issuance was gated on an honest, un-revealed victim's presentation.*
- **`a1_attack_witness`** (exists-trace, `VULNERABLE` only) — a concrete trace exhibiting the attack: the credential is bound to the adversary's key, carries the victim's subject, and is learned by the adversary (`K(cred)`), with **no `Reveal_CI` and no `Reveal_HolderKey` anywhere** — the adversary uses only its own freshly generated key.
- **`a1_holder_continuity_{vuln,nonce,fixed}`** (all-traces) — *the issued credential's holder key equals the presented holder key.* Falsified under `VULNERABLE` and `FIXED_NONCE`; verified under `FIXED`.
- **`a1_holder_authorization_txdata`** (all-traces, `FIXED_TXDATA`) — *the issued credential's holder key was committed to by the victim during the presentation* (the unlinkability-preserving authorization property, allowing the issued key to differ from the presented key).

Proof heuristics (custom tactics): **`a1_witness_tactic`**, **`a1_continuity_tactic`**, **`a1_impersonation_tactic`** prioritize the protocol action facts (`CI_Issued`, `AdversaryKey`, presentation/authorization facts) and de-prioritize adversary key-knowledge (`!KU`) deductions, so the relevant proofs terminate quickly under `--prove`.

## Model design and abstractions

- **Cryptography.** Tamarin builtins for signing and hashing; public-key encryption is modelled with `penc/3` + `pdec/2` (for JWE-style response encryption). The Access Token is a private opaque term `aToken/3` bound to the `auth_session` and the Issuer, so possession of the token folds the OAuth / PAR / token endpoint into one object that gates the Credential Endpoint.
- **Channels.** TLS is abstracted as the Dolev–Yao `In`/`Out` network — the adversary controls message delivery.
- **Honest Prerequisite Issuer (`PI`).** Prerequisite credentials are unforgeable and issued only to honest holders, so every issuance in the model is genuinely gated on a real honest-holder presentation (the victim premise is never vacuous). There is no `Reveal` rule for `PI`.
- **Adversary.** A malicious / compromised split-architecture Wallet backend (spec §13.4), or, equivalently, a Dolev–Yao attacker that runs its own `auth_session` with `CI` and relays the victim's presentation. It uses only its own freshly generated key (`Adversary_Wallet_Key`). `Reveal` rules for the Issuer key and the victim holder key exist in the model but are **not used** by the attack.
- **DPoP omitted** — orthogonal: it sender-constrains the Access Token to the transport key, not the holder/issuance key, so it gives no uplift against this attack.
- **Scope.** A single derived-credential dataset; carry-and-verify credential signatures; batch issuance (the `proofs` array) is not modelled.

## Limitations and scope

- The continuity fix (`FIXED`) forces the issued credential's holder key to equal the presented one, which conflicts with fresh-`pkH`-per-credential privacy patterns; the commitment fix (`FIXED_TXDATA`) avoids this.
- A malicious Prerequisite Issuer is a distinct, stronger compromise that is out of scope (and not required for this attack).
- Batch issuance is not modelled; the proposed binding would need to apply per proof in the `proofs` array.
- If the holder / commitment private keys themselves reside in (and are taken from) a compromised backend rather than the device-side trust domain, the fix reduces to the full-Wallet-compromise case, which no protocol can distinguish from the legitimate holder. The value of the result derives from the §13.4 trust boundary, where the holder key is *not* in the compromised backend.

## How to cite

If you use this model, please cite it as:

```
MURAT SEKMEN. "Formal Symbolic Analysis of a Cross-Session Holder-Binding
Confusion in the OpenID4VCI Interactive Authorization Endpoint."
2026. <github.com/congenial-max/OpenID4VCI_v1-1_IAE_cross-session-holder-binding-confusion_FormalSecurityAnalysis>.
```

## References

- OpenID for Verifiable Credential Issuance **1.1**, editor's draft `openid-4-verifiable-credential-issuance-1_1-01`.
- OpenID for Verifiable Presentations (for `transaction_data` and the KB-JWT holder-binding mechanism).
- D. Fett, T. Lodderstedt — *Security and Trust in the OpenID4VC Ecosystem* (companion document); holder-binding requirements I-40 and P-50.
- RFC 7800 — Proof-of-Possession Key Semantics for JWTs.
- RFC 7638 — JSON Web Key (JWK) Thumbprint.
- D. Basin, C. Cremers, J. Dreier, R. Sasse — *The Tamarin Prover for the Symbolic Analysis of Security Protocols*, and the Tamarin manual: <https://tamarin-prover.github.io/manual/>.

## Contact

For questions about the model or the disclosed attack, please open a GitHub issue or contact sekmenmu20@itu.edu.tr.
