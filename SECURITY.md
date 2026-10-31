# Security Policy

## Reporting a Vulnerability

For this fork, contact **camo007@duck.com** privately. Do not open a public issue
or pull request containing an undisclosed vulnerability or working exploit.
Blockstream does not maintain this fork or receive its security reports.

Encrypt sensitive reports using the [security-reporting public key](doc/security-reporting-key.asc)
before emailing them. Its primary fingerprint is:

`CF20 24F4 3046 8AF2 657D 6A2E 41E1 57DB 4FED F04E`

The key identifies `Elements+ Security <camo007@duck.com>`, was generated on
2026-10-23, and expires on 2027-10-23. It has an Ed25519 signing/certification
key and a Curve25519 encryption subkey. Verify the full fingerprint through a
trusted maintainer channel before sending sensitive details; a key hosted
alongside the code is not independent authentication of the maintainer.

Ordinary email is not end-to-end encrypted. If you cannot use OpenPGP, start
with a brief, non-sensitive description and request a secure channel. Keep
email subjects non-sensitive even when encrypting attachments.

Include the affected commit and network identity, impact, prerequisites,
reproduction steps using isolated test assets, relevant redacted logs, and any
proposed fix. Never include seed phrases, private keys, RPC cookies, passwords,
TLS private keys, or other users' data. Do not test exploits against live users.

Coordinate disclosure timing with the maintainer. Issues affecting upstream
Elements, Bitcoin, or other dependencies should also be reported through those
projects' own security policies, without assuming that this fork's contact
automatically reaches them.

## Scope and Support

Report issues in consensus, deposits, withdrawals, RPC transport, dependencies,
and release artifacts. State the exact source SHA and binary checksum. The node uses a production identity targeting mainnet. Independent audits
should be identified by their published scope and report. Historical slot-5 tools and obsolete network identities are not
supported deployments.
