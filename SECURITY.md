# Security Policy

## What this repository is

A **verifier**. It reads review ledgers and recomputes hashes and signatures.
It does not run the reviewed code, does not execute ledger contents, and does not
talk to a network.

## Reporting a vulnerability

Open a private report through GitHub:
**Security → Report a vulnerability** on this repository, or email the maintainer
listed on the GitHub profile.

Please do not open a public issue for:

- a way to make a **tampered ledger verify as valid** (this is the most serious class of bug);
- a way to make a **valid ledger fail** without the ledger being wrong;
- signature verification bypass, hash collision tricks, JCS canonicalization
  mismatches that alter verification results;
- denial of service on very large ledgers.

## What we consider in scope

| In scope | Out of scope |
|---|---|
| Verifier correctness (false accept / false reject) | The review engine, which is not in this repo |
| The JS kernel in `verifier/` (hand-written crypto) | Third-party services |
| Canonicalization differences between Python and JS | The quality of a review |
| Path handling when a case directory is moved | Anything requiring write access to the ledger |

## Known limitations (by design, not vulnerabilities)

- A signature proves *who issued the events*, not that the review was correct.
- The ledger prevents **post-hoc edits**, not **fabrication at the start**.
- Public key distribution is out of scope: obtain the fingerprint through a
  channel you already trust.
- `verify.html` covers chain / signatures / digest / manifest. Business rules
  (phases, roles, leases) are covered only by the Python verifier.

## Disclosure

We aim to acknowledge within 5 working days. Fixes for verification-bypass bugs
take priority over everything else in this project.
