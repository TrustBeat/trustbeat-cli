# trustbeat

[![Crates.io](https://img.shields.io/crates/v/trustbeat.svg)](https://crates.io/crates/trustbeat)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Anchor files to **qualified eIDAS timestamps** and verify the proofs **offline**.

A single static binary. Your files never leave your machine — only their SHA-256
digest is transmitted.

Part of **[TrustBeat](https://trustbeat.eu/en)** — digital trust infrastructure for the EU.
Prefer a library? Python, TypeScript, Java, C# and Go SDKs: **[trustbeat.eu/en/sdks](https://trustbeat.eu/en/sdks)**.

```console
$ trustbeat anchor contract.pdf --wait
✓ sha256   9f2a1c…4b7e   contract.pdf
✓ submitted 01KNBQMYC0AQ7KA561TNKK71GJ
✓ anchored
  time     2026-07-22T09:14:03Z
  tsa      SK TIMESTAMPING UNIT 2025E
  proof    contract.pdf.proof.json

$ trustbeat verify contract.pdf.proof.json contract.pdf
✓ document   SHA-256 matches the anchored hash
✓ merkle     14 path step(s) re-derive the batch root
✓ timestamp  token imprint (SHA-256) equals the batch root
✓ signature  signed by SK TIMESTAMPING UNIT 2025E

PROOF VALID
```

## Install

```bash
cargo install trustbeat
```

No Rust toolchain? You can also [build from source](#building-from-source).
Prebuilt binaries for Linux, macOS and Windows are coming with the first tagged
[release](https://github.com/TrustBeat/trustbeat-cli/releases).

## Verification works offline, forever

`trustbeat verify` makes **no network calls and needs no API key**. It re-derives
the cryptography from the proof bundle alone:

| Check | What it proves |
|---|---|
| `document` | SHA-256 of your file equals the hash in the proof |
| `merkle` | The proof path re-derives the batch's Merkle root |
| `timestamp` | The RFC 3161 token's `messageImprint` **is** that Merkle root |
| `signature` | The TSA's signature verifies against the certificate in the token |

The `timestamp` check is the one that matters most: it's the join between your
document's Merkle path and the qualified token. Without it, a valid token could
be paired with an unrelated tree.

This means a proof outlives us. If TrustBeat disappeared tomorrow, every proof
ever issued stays verifiable with this binary — or by hand with `openssl`, see
[MANUAL_VERIFICATION.md](https://github.com/TrustBeat/eu-security-app/blob/main/docs/MANUAL_VERIFICATION.md).

### Supported token algorithms

Timestamp tokens vary by TSA, so `verify` handles both common signature families:

| | Supported |
|---|---|
| Signature | ECDSA (P-256, P-384) with SHA-256/384/512; RSA PKCS#1 v1.5 with SHA-256/384/512 |
| Message imprint | SHA-256, SHA-384, SHA-512 |
| Not supported | RSA-PSS, Ed25519, curves other than P-256/P-384 |

Anything unsupported **fails closed** — it is reported as an unsupported token
and the proof is marked invalid. A token is never accepted because its
algorithm wasn't recognised.

The three algorithm slots in a token are independent and routinely differ: the
message imprint may be SHA-256 while the SignerInfo digest is SHA-512 and the
signature is `ecdsa-with-SHA512`. For ECDSA the prehash is chosen by the
*signature* algorithm OID, not the SignerInfo digest.

### Scope limit: certificate chains

`verify` checks that the token's signature is internally consistent against the
certificate embedded in the token. It does **not** validate that certificate's
chain up to a trusted eIDAS root, and does not check revocation. For a full
qualified-status assessment against the EU Trusted List, use the API's
`/v1/verify/signature` endpoint or the portal.

## Commands

### `trustbeat anchor`

```bash
trustbeat anchor report.pdf                # submit, return a tracking id
trustbeat anchor report.pdf --wait         # ...and wait for the proof (~10 min)
trustbeat anchor --hash <64-hex>           # anchor a digest you computed yourself
trustbeat anchor report.pdf -o proof.json  # choose where the proof lands
```

Anchors are batched into a Merkle tree and timestamped roughly every 10 minutes,
so `--wait` can take that long. Without `--wait` the command returns instantly
and you collect the proof later with `trustbeat proof <id>`.

### `trustbeat verify`

```bash
trustbeat verify proof.json                # internal consistency only
trustbeat verify proof.json report.pdf     # also bind the proof to your file
cat proof.json | trustbeat verify -        # read from stdin
```

Exit codes: `0` valid, `1` invalid, `2` usage/IO error.

### `trustbeat proof`

```bash
trustbeat proof 01KNBQMYC0AQ7KA561TNKK71GJ
trustbeat proof <id> --wait -o proof.json
```

Exits `3` when the anchor is still pending.

### `trustbeat hash`

```bash
trustbeat hash report.pdf   # SHA-256, nothing sent anywhere
```

## Configuration

`anchor` and `proof` need an API key ([get one](https://trustbeat.eu/register)).
`verify` and `hash` never do.

Resolution order:

1. `--api-key` / `--api-url`
2. `TRUSTBEAT_API_KEY` / `TRUSTBEAT_API_URL`
3. `~/.config/trustbeat/credentials`

```ini
# ~/.config/trustbeat/credentials
api_key = tb_live_...
```

## Scripting

Every command takes `--json`:

```bash
trustbeat verify proof.json --json | jq -e '.valid'
trustbeat hash report.pdf --json | jq -r '.sha256'
```

Colour follows [NO_COLOR](https://no-color.org) and is disabled when stdout is
not a terminal.

## Building from source

```bash
cargo build --release
cargo test
```

## Documentation

Full API reference and guides at [api.trustbeat.eu/docs](https://api.trustbeat.eu/docs).

This CLI covers file anchoring. The same qualified-timestamp infrastructure also
backs:

| | |
|---|---|
| [Tamper-Evident Logs](https://trustbeat.eu/en/products/tamper-evident-logs) | Sealed log trails for NIS2 Article 21 |
| [AI Decision Anchoring](https://trustbeat.eu/en/products/ai-decision-anchoring) | Provable records of model decisions |
| [Audit Trail](https://trustbeat.eu/en/products/audit-trail) | Append-only, independently verifiable event history |
| [EU Digital Identity](https://trustbeat.eu/en/products/eu-digital-identity) | EUDI Wallet / eIDAS 2 credential verification |
| [Signature Verification](https://trustbeat.eu/en/verify-signature) | Full qualified-status assessment against the EU Trusted List |

Free tier — 100 anchors a month, no card: **[trustbeat.eu/en/pricing](https://trustbeat.eu/en/pricing)**.

## License

MIT © Trustbeat s.r.o.
