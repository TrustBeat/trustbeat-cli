//! Full offline verification of a proof bundle.
//!
//! Four independent checks, all local:
//!
//! 1. **Document binding** (only when a file is supplied) — SHA-256 of the file
//!    equals `proof.hash`.
//! 2. **Merkle inclusion** — the proof path re-derives `proof.merkle_root`.
//! 3. **Timestamp binding** — the token's `messageImprint` equals that same
//!    Merkle root. This is the join that makes step 2 meaningful: without it a
//!    valid token could be paired with an unrelated tree.
//! 4. **Token authenticity** — the TSA's signature over the token verifies
//!    against the certificate embedded in it.
//!
//! A proof is only trustworthy when every applicable check passes.

use self::base64_lite::decode_base64;

use crate::merkle::{self};
use crate::proof::Proof;
use crate::rfc3161::{self, TokenInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Pass,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Fail,
            detail: detail.into(),
        }
    }
    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Skipped,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub checks: Vec<Check>,
    pub token: Option<TokenInfo>,
}

impl Outcome {
    /// Valid only if nothing failed and at least one check actually ran.
    pub fn is_valid(&self) -> bool {
        !self.checks.iter().any(|c| c.status == CheckStatus::Fail)
            && self.checks.iter().any(|c| c.status == CheckStatus::Pass)
    }
}

/// Verifies a proof bundle. `document_hash` is the SHA-256 of the original file,
/// when the caller has it; pass `None` to verify the proof's internal
/// consistency only.
pub fn verify_proof(proof: &Proof, document_hash: Option<&str>) -> Outcome {
    let mut checks = Vec::new();

    // 1. document binding
    match document_hash {
        Some(h) if h.eq_ignore_ascii_case(&proof.hash) => {
            checks.push(Check::pass("document", "SHA-256 matches the anchored hash"));
        }
        Some(h) => {
            checks.push(Check::fail(
                "document",
                format!("file hashes to {h} but the proof anchors {}", proof.hash),
            ));
        }
        None => checks.push(Check::skip(
            "document",
            "no file supplied — proof checked for internal consistency only",
        )),
    }

    // 2. Merkle inclusion
    match merkle::verify_inclusion(
        &proof.hash,
        &proof.proof_path,
        &proof.merkle_root,
        proof.merkle_algorithm.as_deref(),
    ) {
        Ok(true) => checks.push(Check::pass(
            "merkle",
            format!(
                "{} path step(s) re-derive the batch root",
                proof.proof_path.len()
            ),
        )),
        Ok(false) => checks.push(Check::fail(
            "merkle",
            "proof path does not re-derive the stated merkle_root",
        )),
        Err(e) => checks.push(Check::fail("merkle", e.to_string())),
    }

    // 3 + 4. the RFC 3161 token
    let token = match decode_token(&proof.token) {
        Err(e) => {
            checks.push(Check::fail("timestamp", e));
            None
        }
        Ok(der) => match rfc3161::inspect(&der) {
            Err(e) => {
                checks.push(Check::fail("timestamp", e.to_string()));
                None
            }
            Ok(info) => {
                // 3. does the token cover *this* tree?
                if info
                    .message_imprint
                    .eq_ignore_ascii_case(&proof.merkle_root)
                {
                    checks.push(Check::pass(
                        "timestamp",
                        format!(
                            "token imprint ({}) equals the batch root",
                            rfc3161::digest_name(&info.imprint_algorithm)
                        ),
                    ));
                } else {
                    checks.push(Check::fail(
                        "timestamp",
                        format!(
                            "token covers {} but the proof claims root {}",
                            info.message_imprint, proof.merkle_root
                        ),
                    ));
                }
                // 4. is the token authentic?
                if info.signature_valid {
                    checks.push(Check::pass(
                        "signature",
                        format!("signed by {}", short_subject(&info.signer_subject)),
                    ));
                } else {
                    checks.push(Check::fail(
                        "signature",
                        "TSA signature does not verify against the embedded certificate",
                    ));
                }
                Some(info)
            }
        },
    };

    Outcome { checks, token }
}

fn decode_token(token_b64: &str) -> Result<Vec<u8>, String> {
    if token_b64.is_empty() {
        return Err("proof contains no timestamp token".into());
    }
    decode_base64(token_b64).map_err(|_| "timestamp token is not valid base64".to_string())
}

/// Pulls CN= out of an RFC 4514 distinguished name for display.
pub fn short_subject(dn: &str) -> String {
    dn.split(',')
        .find_map(|part| part.trim().strip_prefix("CN=").map(|s| s.to_string()))
        .unwrap_or_else(|| dn.to_string())
}

/// Minimal standard-base64 decoder — avoids a dependency for one call site.
mod base64_lite {
    pub fn decode_base64(input: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::with_capacity(input.len() / 4 * 3);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for c in input.bytes() {
            if c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' {
                continue;
            }
            if c == b'=' {
                break;
            }
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return Err(()),
            } as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        Ok(out)
    }
}

/// Re-exported so `main` can decode a token for display without pulling in a
/// base64 crate.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    base64_lite::decode_base64(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = include_str!("../tests/fixtures/demo-proof.json");
    /// RSA fixtures come from a throwaway self-signed TSA created with
    /// `openssl ts` — they are NOT qualified timestamps. They exist because the
    /// production fallback provider may sign with RSA rather than ECDSA, and
    /// the demo token only exercises the ECDSA path.
    const RSA_SHA256: &str = include_str!("../tests/fixtures/rsa-sha256-proof.json");
    const RSA_SHA512: &str = include_str!("../tests/fixtures/rsa-sha512-proof.json");

    fn demo_proof() -> Proof {
        serde_json::from_str(DEMO).unwrap()
    }

    fn status_of(o: &Outcome, name: &str) -> CheckStatus {
        o.checks
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .status
            .clone()
    }

    #[test]
    fn a_real_proof_verifies_end_to_end() {
        let p = demo_proof();
        let o = verify_proof(&p, Some(&p.hash));
        assert!(o.is_valid(), "checks: {:?}", o.checks);
        assert_eq!(status_of(&o, "document"), CheckStatus::Pass);
        assert_eq!(status_of(&o, "merkle"), CheckStatus::Pass);
        assert_eq!(status_of(&o, "timestamp"), CheckStatus::Pass);
        assert_eq!(status_of(&o, "signature"), CheckStatus::Pass);
    }

    #[test]
    fn token_metadata_is_extracted() {
        let o = verify_proof(&demo_proof(), None);
        let t = o.token.expect("token should parse");
        assert!(t.signature_valid);
        assert!(t.signer_subject.contains("SK ID Solutions"));
        // genTime must agree with the bundle's anchored_at (2026-04-04T07:53:48Z)
        assert_eq!(t.gen_time_unix, 1775289228);
        assert_eq!(t.serial_number, demo_proof().tsa_serial);
    }

    #[test]
    fn without_a_file_the_document_check_is_skipped_not_passed() {
        let o = verify_proof(&demo_proof(), None);
        assert_eq!(status_of(&o, "document"), CheckStatus::Skipped);
        assert!(o.is_valid());
    }

    #[test]
    fn a_different_document_fails() {
        let p = demo_proof();
        let o = verify_proof(&p, Some(&"ab".repeat(32)));
        assert_eq!(status_of(&o, "document"), CheckStatus::Fail);
        assert!(!o.is_valid());
    }

    #[test]
    fn tampering_with_the_root_breaks_the_timestamp_binding() {
        // The token still verifies on its own, but it no longer covers this tree.
        let mut p = demo_proof();
        p.merkle_root = "ff".repeat(32);
        let o = verify_proof(&p, None);
        assert_eq!(status_of(&o, "timestamp"), CheckStatus::Fail);
        assert!(!o.is_valid());
    }

    /// Re-encodes DER as standard base64 so tests can mutate token bytes directly.
    fn encode_base64(data: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn base64_round_trips_through_the_test_encoder() {
        let p = demo_proof();
        let der = base64_decode(&p.token).unwrap();
        assert_eq!(base64_decode(&encode_base64(&der)).unwrap(), der);
    }

    #[test]
    fn tampering_with_the_signature_is_caught() {
        // The ECDSA signature sits at the tail of the SignedData structure.
        let mut p = demo_proof();
        let mut der = base64_decode(&p.token).unwrap();
        let last = der.len() - 1;
        der[last] ^= 0xff;
        p.token = encode_base64(&der);
        let o = verify_proof(&p, None);
        assert!(!o.is_valid(), "a mutated signature must not verify");
    }

    #[test]
    fn tampering_with_the_timestamped_hash_is_caught() {
        // Locate the messageImprint inside the token and flip each of its bytes.
        // This is the field that says *what* was timestamped, so every single
        // mutation must be caught — either by the messageDigest binding inside
        // the token or by the imprint-vs-merkle_root comparison.
        let p = demo_proof();
        let der = base64_decode(&p.token).unwrap();
        let root = crate::merkle::hex_decode(&p.merkle_root).unwrap();
        let at = der
            .windows(root.len())
            .position(|w| w == root.as_slice())
            .expect("merkle root must appear in the token as the messageImprint");

        for i in 0..root.len() {
            let mut mutated = der.clone();
            mutated[at + i] ^= 0x01;
            let mut q = demo_proof();
            q.token = encode_base64(&mutated);
            assert!(
                !verify_proof(&q, None).is_valid(),
                "mutating imprint byte {i} must invalidate the proof"
            );
        }
    }

    // ── RSA tokens ───────────────────────────────────────────────────────────
    // The demo token is ECDSA (P-256 / ecdsa-with-SHA512). A TSA may equally
    // sign with RSA PKCS#1 v1.5, so both code paths need real coverage.

    #[test]
    fn an_rsa_signed_token_verifies() {
        let p: Proof = serde_json::from_str(RSA_SHA256).unwrap();
        let o = verify_proof(&p, Some(&p.hash));
        assert!(o.is_valid(), "checks: {:?}", o.checks);
        assert!(o.token.unwrap().signature_valid);
    }

    #[test]
    fn an_rsa_token_with_a_sha512_signer_digest_verifies() {
        // digestAlgorithm and the imprint algorithm differ here (SHA-512 vs
        // SHA-256) — they must not be conflated.
        let p: Proof = serde_json::from_str(RSA_SHA512).unwrap();
        let o = verify_proof(&p, Some(&p.hash));
        assert!(o.is_valid(), "checks: {:?}", o.checks);
    }

    #[test]
    fn a_tampered_rsa_signature_is_caught() {
        let mut p: Proof = serde_json::from_str(RSA_SHA256).unwrap();
        let mut der = base64_decode(&p.token).unwrap();
        let last = der.len() - 1;
        der[last] ^= 0xff;
        p.token = encode_base64(&der);
        assert!(!verify_proof(&p, None).is_valid());
    }

    #[test]
    fn the_signer_certificate_is_chosen_by_timestamping_eku() {
        // The RSA fixtures embed the TSA leaf *and* its CA. Picking the wrong
        // one would fail the signature check, so a pass proves EKU selection.
        let p: Proof = serde_json::from_str(RSA_SHA256).unwrap();
        let t = verify_proof(&p, None).token.expect("token parses");
        assert!(
            t.signer_subject.contains("Timestamping Unit"),
            "expected the leaf TSA cert, got {}",
            t.signer_subject
        );
    }

    #[test]
    fn an_unsupported_key_algorithm_fails_closed() {
        // Rewrite the signer key's rsaEncryption OID (1.2.840.113549.1.1.1) to
        // rsassaPss (1.2.840.113549.1.1.10) — same encoded length, last byte
        // 0x01 -> 0x0A. RSA-PSS is not implemented; it must be reported as
        // unsupported, never silently accepted.
        let mut p: Proof = serde_json::from_str(RSA_SHA256).unwrap();
        let mut der = base64_decode(&p.token).unwrap();
        const RSA_ENC_OID: [u8; 11] = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        ];
        let at = der
            .windows(RSA_ENC_OID.len())
            .position(|w| w == RSA_ENC_OID)
            .expect("rsaEncryption OID must appear in the certificate SPKI");
        der[at + 10] = 0x0A;
        p.token = encode_base64(&der);

        let o = verify_proof(&p, None);
        assert!(!o.is_valid(), "an unknown key algorithm must not verify");
    }

    /// Documents a deliberate scope limit: we verify that the token's signature
    /// is internally consistent, NOT that the signing certificate chains to a
    /// trusted eIDAS root. Bytes belonging only to the embedded certificate can
    /// therefore be altered without failing verification. Chain validation
    /// against the EU Trusted List is a separate step — see
    /// docs/MANUAL_VERIFICATION.md and the API's /v1/verify endpoints.
    #[test]
    fn certificate_chain_is_not_validated_offline() {
        let p = demo_proof();
        let o = verify_proof(&p, None);
        assert!(o.is_valid());
        assert!(
            !o.checks.iter().any(|c| c.name == "chain"),
            "if a chain check is ever added, update this test and the README"
        );
    }

    #[test]
    fn a_missing_token_fails_rather_than_silently_passing() {
        let mut p = demo_proof();
        p.token = String::new();
        let o = verify_proof(&p, None);
        assert_eq!(status_of(&o, "timestamp"), CheckStatus::Fail);
        assert!(!o.is_valid());
    }

    #[test]
    fn a_corrupt_proof_path_fails_the_merkle_check() {
        let mut p = demo_proof();
        p.proof_path.push(crate::proof::ProofStep {
            sibling: "cd".repeat(32),
            side: "left".into(),
        });
        let o = verify_proof(&p, None);
        assert_eq!(status_of(&o, "merkle"), CheckStatus::Fail);
        assert!(!o.is_valid());
    }

    #[test]
    fn base64_decoder_matches_known_vectors() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_decode("SGVsbG8sIHdvcmxk").unwrap(), b"Hello, world");
        // whitespace and newlines are tolerated (PEM-style wrapping)
        assert_eq!(base64_decode("TWFu\nTWFu").unwrap(), b"ManMan");
        assert!(base64_decode("!!!!").is_err());
    }

    #[test]
    fn short_subject_extracts_the_common_name() {
        assert_eq!(
            short_subject("C=EE,O=SK ID Solutions AS,CN=DEMO SK TIMESTAMPING UNIT 2025E"),
            "DEMO SK TIMESTAMPING UNIT 2025E"
        );
        assert_eq!(short_subject("O=NoCommonName"), "O=NoCommonName");
    }
}
