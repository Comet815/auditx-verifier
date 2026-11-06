# AuditX Verifier

![verify](https://github.com/Comet815/auditx-verifier/actions/workflows/ci.yml/badge.svg)

**Don't trust me. Recompute it yourself.**

An independent verifier for append-only review ledgers. It checks a hash chain,
per-event Ed25519 signatures, an artifact manifest, and evidence quotes.

It turns "this report is real" from a verbal promise into something anyone can
recompute on their own machine.

```
python verify_review_brain.py examples/case-demo
```

```
✅ V1-V9 all passed (structure / chain / phases / roles / leases / freeze / digest / projection)
   + V10 signatures / V11 evidence
```

![verification passed](docs/verify-pass.png)

---

## Architecture

![architecture](docs/architecture.png)

---

## Why this exists

A software acceptance report is usually a Word file:

- a conclusion can be changed, a finding deleted — **without anyone noticing**;
- the reviewer, the basis for the decision, and the exact version of the code
  are often established verbally;
- when a dispute arises, each side produces its own "final version".

AuditX records the review as an **append-only event ledger**. Each step is
signed, linked by hash, and bound to the exact bytes of the reviewed artifact.
Anyone can verify the record independently, including people who do not trust
the reviewer.

This repository contains the verifier. It **imports no producer code** and
recomputes every hash and signature from scratch.

## Try it in 30 seconds

```bash
pip install jsonschema cryptography
python verify_review_brain.py examples/case-demo
```

Alternatively, open `examples/case-demo/verify.html`. It needs **no installation
and no network** and runs the same checks in your browser, in pure JavaScript
with no third-party libraries.

## Live demo

**[comet815.github.io/auditx-verifier](https://comet815.github.io/auditx-verifier/)**

- the original ledger → green "verified";
- a tampered ledger, one word changed → red "verification failed".

## What it checks

| ID | Check | Notes |
|---|---|---|
| V1 | Structure | 12-field envelope, ULID event ids |
| V2 | JSON Schema | per-event schema (`findings.schema.json`) |
| V3 | Chain | seq continuity, `prev_hash`, per-line hash recomputation |
| V4 | Phases | each event must appear in a legal phase |
| V5 | Roles | role allowlist: who may write which event |
| V6 | Leases | seat lease not expired |
| V7 | Frozen | no writes after freeze |
| V8 | Digest | final digest matches finding counts |
| V9 | Projection | `view.json` matches replayed state |
| V10 | Signatures | Ed25519 per-event verification |
| V11 | Evidence | artifact hashes, snapshot, quotes must really exist |

The browser build covers C1–C7 (chain, signatures, digest, manifest) — enough to
answer "was this report altered". Business rules are covered only by the Python
verifier.

## Design principles

- **Zero shared logic** — the verifier never imports the producer. If the
  producer has a bug, the verifier catches it.
- **Plain text** — the ledger is JSONL: diffable, greppable, openable in Notepad.
- **Offline** — no network, no upload, no cloud.
- **Portable** — a case directory can be copied to another machine and still
  verify, because the manifest stores relative paths.

## Boundaries (important)

- It verifies that **the record was not altered**, not that the review was any
  good.
- A signature proves that the holder of a key issued these events. It does not
  prove that the issuer is honest.
- **Trust begins with the public key.** Obtain its fingerprint through a channel
  you already trust — a contract annex, a published page — not from the
  `pubkey.pem` shipped with the case.
- The ledger prevents *post-hoc edits*, not *fabrication at the start*. Blind
  review, cross-examination and sampling are what address that.

## Repository layout

```
verify_review_brain.py     CLI verifier (V1-V11)
findings.schema.json       event JSON Schema
verifier/
  verifier_core.js         browser kernel (SHA-256 / SHA-512 / Ed25519, hand-written)
  shell.html               page template
  test_verifier.js         16 checks, incl. 5 tamper cases
examples/case-demo/        clean review: 12 signed events, 0 findings rejected
examples/case-handoff/     a script that passes the gates but should not ship
docs/                      screenshots
.github/workflows/ci.yml   Python + Node, on Linux and Windows
```

## Tests

```bash
python verify_review_brain.py examples/case-demo   # V1-V11
node verifier/test_verifier.js                     # 16 kernel checks
```

## Security

Bugs in the verifier itself — above all, anything that would let a tampered
ledger verify as valid — should go through GitHub's private vulnerability
reporting, not a public issue. Scope and known limitations: [SECURITY.md](SECURITY.md).

## Related

The producer (the review engine) is not open source; this repository contains the
verifier only, on purpose. The sister project
[Hummingbird](https://github.com/Comet815/hummingbird) is a separate production
pipeline and is unrelated to this repository.

## License

MIT © 2026 Qingbeilu

---

[中文](README.md) · **English**
