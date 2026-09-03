//! Merkle inclusion-proof verification.
//!
//! Mirrors `MerkleVerifier.scala` and every SDK implementation (see
//! `sdk/go/verify.go`). The fold depends on the construction the proof declares
//! in `merkle_algorithm`:
//!
//! ```text
//! trustbeat-legacy-sha256   leaf   = your hash
//!                           parent = SHA-256(left || right)
//!
//! rfc6962-sha256            leaf   = SHA-256(0x00 || your hash)
//!                           parent = SHA-256(0x01 || left || right)
//! ```
//!
//! Each step's `side` gives the *sibling's* position, so:
//!
//! - `"left"`  → sibling is the left child → hash over (sibling, current)
//! - `"right"` → sibling is the right child → hash over (current, sibling)
//!
//! A proof with no `merkle_algorithm` predates the field and is legacy.

use sha2::{Digest, Sha256};

use crate::proof::ProofStep;

/// The original TrustBeat construction.
pub const LEGACY_SHA256: &str = "trustbeat-legacy-sha256";

/// RFC 6962 / RFC 9162.
pub const RFC6962_SHA256: &str = "rfc6962-sha256";

/// Leaf and node prefixes for a declared algorithm.
///
/// `None` (absent on the wire) means legacy. An unrecognised name is an error,
/// never a silent fallback: "unsupported" and "forged" must not look alike.
fn prefixes(algorithm: Option<&str>) -> Result<(&'static [u8], &'static [u8]), MerkleError> {
    match algorithm.unwrap_or(LEGACY_SHA256) {
        LEGACY_SHA256 => Ok((&[], &[])),
        RFC6962_SHA256 => Ok((&[0x00], &[0x01])),
        other => Err(MerkleError::UnsupportedAlgorithm(other.to_string())),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    BadLeafHex(String),
    BadSiblingHex { step: usize, value: String },
    UnknownSide { step: usize, side: String },
    BadRootHex(String),
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLeafHex(v) => write!(f, "invalid leaf hash hex: {v:?}"),
            Self::BadSiblingHex { step, value } => {
                write!(f, "invalid sibling hex at step {step}: {value:?}")
            }
            Self::UnknownSide { step, side } => {
                write!(
                    f,
                    "unknown side {side:?} at step {step}: want \"left\" or \"right\""
                )
            }
            Self::BadRootHex(v) => write!(f, "invalid merkle_root hex: {v:?}"),
            Self::UnsupportedAlgorithm(v) => write!(
                f,
                "unsupported merkle_algorithm {v:?}: this build understands {LEGACY_SHA256:?} \
                 and {RFC6962_SHA256:?}; upgrade the CLI, or verify via the API"
            ),
        }
    }
}

impl std::error::Error for MerkleError {}

/// Re-derives the Merkle root from `leaf_hash` and the proof path.
pub fn derive_root(
    leaf_hash: &str,
    path: &[ProofStep],
    algorithm: Option<&str>,
) -> Result<Vec<u8>, MerkleError> {
    let (leaf_prefix, node_prefix) = prefixes(algorithm)?;

    let mut current =
        hex_decode(leaf_hash).ok_or_else(|| MerkleError::BadLeafHex(leaf_hash.to_string()))?;
    if !leaf_prefix.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(leaf_prefix);
        hasher.update(&current);
        current = hasher.finalize().to_vec();
    }

    for (i, step) in path.iter().enumerate() {
        let sibling = hex_decode(&step.sibling).ok_or_else(|| MerkleError::BadSiblingHex {
            step: i,
            value: step.sibling.clone(),
        })?;
        let mut hasher = Sha256::new();
        hasher.update(node_prefix);
        match step.side.as_str() {
            "left" => {
                hasher.update(&sibling);
                hasher.update(&current);
            }
            "right" => {
                hasher.update(&current);
                hasher.update(&sibling);
            }
            other => {
                return Err(MerkleError::UnknownSide {
                    step: i,
                    side: other.to_string(),
                })
            }
        }
        current = hasher.finalize().to_vec();
    }
    Ok(current)
}

/// Re-derives the root and compares it to `expected_root` in constant time.
pub fn verify_inclusion(
    leaf_hash: &str,
    path: &[ProofStep],
    expected_root: &str,
    algorithm: Option<&str>,
) -> Result<bool, MerkleError> {
    let derived = derive_root(leaf_hash, path, algorithm)?;
    let expected = hex_decode(expected_root)
        .ok_or_else(|| MerkleError::BadRootHex(expected_root.to_string()))?;
    Ok(constant_time_eq(&derived, &expected))
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Constant-time byte comparison — no early return on first mismatch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(sibling: &str, side: &str) -> ProofStep {
        ProofStep {
            sibling: sibling.to_string(),
            side: side.to_string(),
        }
    }

    fn sha256_hex(parts: &[&[u8]]) -> String {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        hex_encode(&h.finalize())
    }

    #[test]
    fn legacy_single_leaf_batch_root_is_the_leaf() {
        // A batch of one under the legacy tree: empty proof path, root == leaf
        // (matches demo-proof.json).
        let leaf = "264234150e0c34cde02b241cefb0dd13751231f0fa0e202c6eb18e79ab9321a4";
        assert!(verify_inclusion(leaf, &[], leaf, None).unwrap());
    }

    #[test]
    fn sibling_on_the_right_hashes_current_first() {
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let expected = sha256_hex(&[&hex_decode(&leaf).unwrap(), &hex_decode(&sib).unwrap()]);
        assert!(verify_inclusion(&leaf, &[step(&sib, "right")], &expected, None).unwrap());
    }

    #[test]
    fn sibling_on_the_left_hashes_sibling_first() {
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let expected = sha256_hex(&[&hex_decode(&sib).unwrap(), &hex_decode(&leaf).unwrap()]);
        assert!(verify_inclusion(&leaf, &[step(&sib, "left")], &expected, None).unwrap());
    }

    #[test]
    fn side_is_not_commutative() {
        // The same sibling on the other side must NOT produce the same root,
        // otherwise the proof would prove nothing about position.
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let root_right = derive_root(&leaf, &[step(&sib, "right")], None).unwrap();
        let root_left = derive_root(&leaf, &[step(&sib, "left")], None).unwrap();
        assert_ne!(root_right, root_left);
    }

    #[test]
    fn multi_step_path_climbs_the_tree() {
        let leaf = "11".repeat(32);
        let s1 = "22".repeat(32);
        let s2 = "33".repeat(32);
        let level1 = sha256_hex(&[&hex_decode(&leaf).unwrap(), &hex_decode(&s1).unwrap()]);
        let root = sha256_hex(&[&hex_decode(&s2).unwrap(), &hex_decode(&level1).unwrap()]);
        assert!(verify_inclusion(&leaf, &[step(&s1, "right"), step(&s2, "left")], &root, None).unwrap());
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let expected = sha256_hex(&[&hex_decode(&leaf).unwrap(), &hex_decode(&sib).unwrap()]);
        let tampered = "ab".repeat(32);
        assert!(!verify_inclusion(&tampered, &[step(&sib, "right")], &expected, None).unwrap());
    }

    #[test]
    fn tampered_root_fails() {
        let leaf = "aa".repeat(32);
        assert!(!verify_inclusion(&leaf, &[], &"cc".repeat(32), None).unwrap());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_false_negative() {
        assert_eq!(
            verify_inclusion("zz", &[], &"aa".repeat(32), None).unwrap_err(),
            MerkleError::BadLeafHex("zz".into())
        );
        assert_eq!(
            verify_inclusion(&"aa".repeat(32), &[step("zz", "left")], &"aa".repeat(32), None)
                .unwrap_err(),
            MerkleError::BadSiblingHex {
                step: 0,
                value: "zz".into()
            }
        );
        assert_eq!(
            verify_inclusion(
                &"aa".repeat(32),
                &[step(&"bb".repeat(32), "up")],
                &"aa".repeat(32),
                None
            )
            .unwrap_err(),
            MerkleError::UnknownSide {
                step: 0,
                side: "up".into()
            }
        );
    }

    #[test]
    fn odd_length_hex_is_rejected() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("abcd").is_some());
    }

    #[test]
    fn constant_time_eq_matches_normal_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    // ── merkle_algorithm dispatch (CLI 0.2.0) ─────────────────────────────

    #[test]
    fn absent_algorithm_is_legacy() {
        // Proofs issued before the field existed must keep verifying forever.
        let leaf = "aa".repeat(32);
        assert!(verify_inclusion(&leaf, &[], &leaf, None).unwrap());
        assert!(verify_inclusion(&leaf, &[], &leaf, Some(LEGACY_SHA256)).unwrap());
    }

    #[test]
    fn rfc6962_hashes_the_leaf() {
        let leaf = "aa".repeat(32);
        let rfc_root = sha256_hex(&[&[0x00], &hex_decode(&leaf).unwrap()]);
        assert!(verify_inclusion(&leaf, &[], &rfc_root, Some(RFC6962_SHA256)).unwrap());
        // Under rfc6962 a one-leaf root is not the leaf itself.
        assert!(!verify_inclusion(&leaf, &[], &leaf, Some(RFC6962_SHA256)).unwrap());
    }

    #[test]
    fn rfc6962_reference_vector() {
        // MTH([SHA256("a"), SHA256("b"), SHA256("c")]) per RFC 6962, leaf 0.
        let a = sha256_hex(&[b"a"]);
        let path = [
            step("a0d9f0a50b35b9f7d7edc57fb64f4771ddef0fefeaca4e6f949a1514db5b136d", "right"),
            step("6a3fc11b79f836bda340e75c8906e961b8adf4d6a08a2b992e3f38cd6ff38ebf", "right"),
        ];
        let root = "cac3d448d4e20a2ad5eae1f500e63c2a7f9217cd14572ba7fd22e26dc1ec2648";
        assert!(verify_inclusion(&a, &path, root, Some(RFC6962_SHA256)).unwrap());
    }

    // Vectors below are taken verbatim from Google's transparency-dev/merkle
    // (rfc6962_test.go) — a third-party implementation. Our own arithmetic only
    // proves self-consistency; these prove conformance.
    const UPSTREAM_ENTRY: &str = "4c313233343536"; // hex of "L123456"
    const UPSTREAM_LEAF: &str = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56";
    const UPSTREAM_EMPTY_LEAF: &str = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
    const UPSTREAM_ROOT_2: &str = "bf9ae70442844df993ca0001a7c8a095c5f145857960b1ee389df6cbe84b5bf3";

    #[test]
    fn leaf_hash_matches_upstream_vector() {
        // SHA-256(0x00 || "L123456") per transparency-dev/merkle.
        assert!(
            verify_inclusion(UPSTREAM_ENTRY, &[], UPSTREAM_LEAF, Some(RFC6962_SHA256)).unwrap()
        );
    }

    #[test]
    fn rfc6962_left_sibling_applies_the_node_prefix() {
        // Two-leaf tree whose BOTH leaf hashes are upstream vectors.
        // Exercises side="left", which no other rfc6962 test reaches.
        let path = [step(UPSTREAM_EMPTY_LEAF, "left")];
        assert!(
            verify_inclusion(UPSTREAM_ENTRY, &path, UPSTREAM_ROOT_2, Some(RFC6962_SHA256)).unwrap()
        );
    }

    #[test]
    fn unknown_algorithm_is_an_error_not_a_false_negative() {
        // "I cannot check this" must not look like "this proof is forged".
        let leaf = "aa".repeat(32);
        assert_eq!(
            verify_inclusion(&leaf, &[], &leaf, Some("sha3-512-tree")).unwrap_err(),
            MerkleError::UnsupportedAlgorithm("sha3-512-tree".into())
        );
    }
}
