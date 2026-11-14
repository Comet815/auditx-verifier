# Disclaimer

> This repository is a **verification tool**. It is not legal advice, not a
> forensic conclusion, and not an audit opinion. It answers "was this record
> altered", not "was this review any good".

---

## 1. What it proves, and what it does not

**Proves**: the ledger is self-consistent (structure, hash chain, stages,
permissions, leases, freeze, digest, projection); every event was signed by the
matching key; the byte hashes of the reviewed files and the quoted evidence
really exist and were not swapped.

**Does not prove**:

- that the findings are **correct** — defects can be missed or mis-rated; the
  chain cannot fix that;
- that the signer is **honest** — a signature proves who signed, not who to trust;
- that the reviewed software is **secure, compliant or shippable**;
- **time** — the ledger carries no trusted timestamp and cannot prove *when* the
  events were written. Where time matters, add a third-party timestamp or
  notarisation; do not use the ledger as a clock.

## 2. A green check is not an exemption

Passing verification means the **record and signatures were not altered**. It
does not relieve anyone of liability, and it is not by itself proof of due
diligence — that is decided by contracts, procedure and adjudicators, not by
this tool.

## 3. Trust begins with the public key

How the key reaches you is what gives this mechanism meaning. Check the
fingerprint through an **independent channel** — a contract annex, a published
page — not from the `pubkey.pem` shipped inside the case directory. Replace the
key and re-sign the ledger, and the verifier will honestly report "pass": it
checks self-consistency, not provenance.

## 4. Provided as is, without warranty

This repository is provided **AS IS**, without any express or implied warranty,
including but not limited to merchantability, fitness for a particular purpose,
non-infringement and freedom from errors.

The author does not warrant that the verifier has no missing checks (especially
any defect that would let a tampered ledger verify as valid), that the sample
data fits your case, or that decisions made with it will not cause loss. Please
report such defects privately — see [SECURITY.md](SECURITY.md).

## 5. Limitation of liability

To the maximum extent permitted by applicable law, the author shall not be liable
for any direct, indirect, incidental, special or consequential damages arising
from the use of, or inability to use, this repository, including but not limited
to lost profits, data loss, business interruption, third-party claims and harm to
reputation.

Nothing in this disclaimer excludes or limits liability that cannot be excluded
or limited under applicable law.

## 6. Your responsibilities

- **Lawfulness of case data** — ledgers and evidence may contain personal data,
  client secrets and third-party code. Obtain authorisation and redact before
  storing, transferring or publishing. This tool does not handle compliance for
  you.
- **How you state the result** — wording in contracts, reports and public claims
  is yours. Do not present "the hash chain passed" as "the review was correct".

## 7. Third-party components and trademarks

Depends on `jsonschema`, `cryptography`, Python and Node.js; their licences and
security posture belong to their respective owners — track and upgrade them
yourself. Mentions of models or services are not endorsements.

## 8. Relationship to the licence

[LICENSE](LICENSE) is MIT, which already contains the "as is, no liability"
clause. This document is a **plain-language explanation and supplement**, not a
change to its legal meaning; where they conflict, the MIT text governs.

## 9. Changes

This disclaimer may be updated at any time, effective on publication, without
notice. The version in this repository is authoritative.

---

*Qingbeilu · 2026-11*
