//! Merkle inclusion-proof verification.
//!
//! Mirrors `MerkleEngine.scala` and every SDK implementation (see
//! `sdk/go/verify.go`). The parent of two nodes is:
//!
//! ```text
//! parent = SHA-256(left_child_bytes || right_child_bytes)
//! ```
//!
//! Each step's `side` gives the *sibling's* position, so:
//!
//! - `"left"`  → sibling is the left child → `SHA-256(sibling || current)`
//! - `"right"` → sibling is the right child → `SHA-256(current || sibling)`

use sha2::{Digest, Sha256};

use crate::proof::ProofStep;

#[derive(Debug, PartialEq, Eq)]
pub enum MerkleError {
    BadLeafHex(String),
    BadSiblingHex { step: usize, value: String },
    UnknownSide { step: usize, side: String },
    BadRootHex(String),
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
        }
    }
}

impl std::error::Error for MerkleError {}

/// Re-derives the Merkle root from `leaf_hash` and the proof path.
pub fn derive_root(leaf_hash: &str, path: &[ProofStep]) -> Result<Vec<u8>, MerkleError> {
    let mut current =
        hex_decode(leaf_hash).ok_or_else(|| MerkleError::BadLeafHex(leaf_hash.to_string()))?;

    for (i, step) in path.iter().enumerate() {
        let sibling = hex_decode(&step.sibling).ok_or_else(|| MerkleError::BadSiblingHex {
            step: i,
            value: step.sibling.clone(),
        })?;
        let mut hasher = Sha256::new();
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
) -> Result<bool, MerkleError> {
    let derived = derive_root(leaf_hash, path)?;
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
    fn single_leaf_batch_root_is_the_leaf() {
        // A batch of one: empty proof path, root == leaf (matches demo-proof.json).
        let leaf = "264234150e0c34cde02b241cefb0dd13751231f0fa0e202c6eb18e79ab9321a4";
        assert!(verify_inclusion(leaf, &[], leaf).unwrap());
    }

    #[test]
    fn sibling_on_the_right_hashes_current_first() {
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let expected = sha256_hex(&[&hex_decode(&leaf).unwrap(), &hex_decode(&sib).unwrap()]);
        assert!(verify_inclusion(&leaf, &[step(&sib, "right")], &expected).unwrap());
    }

    #[test]
    fn sibling_on_the_left_hashes_sibling_first() {
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let expected = sha256_hex(&[&hex_decode(&sib).unwrap(), &hex_decode(&leaf).unwrap()]);
        assert!(verify_inclusion(&leaf, &[step(&sib, "left")], &expected).unwrap());
    }

    #[test]
    fn side_is_not_commutative() {
        // The same sibling on the other side must NOT produce the same root,
        // otherwise the proof would prove nothing about position.
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let root_right = derive_root(&leaf, &[step(&sib, "right")]).unwrap();
        let root_left = derive_root(&leaf, &[step(&sib, "left")]).unwrap();
        assert_ne!(root_right, root_left);
    }

    #[test]
    fn multi_step_path_climbs_the_tree() {
        let leaf = "11".repeat(32);
        let s1 = "22".repeat(32);
        let s2 = "33".repeat(32);
        let level1 = sha256_hex(&[&hex_decode(&leaf).unwrap(), &hex_decode(&s1).unwrap()]);
        let root = sha256_hex(&[&hex_decode(&s2).unwrap(), &hex_decode(&level1).unwrap()]);
        assert!(verify_inclusion(&leaf, &[step(&s1, "right"), step(&s2, "left")], &root).unwrap());
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaf = "aa".repeat(32);
        let sib = "bb".repeat(32);
        let expected = sha256_hex(&[&hex_decode(&leaf).unwrap(), &hex_decode(&sib).unwrap()]);
        let tampered = "ab".repeat(32);
        assert!(!verify_inclusion(&tampered, &[step(&sib, "right")], &expected).unwrap());
    }

    #[test]
    fn tampered_root_fails() {
        let leaf = "aa".repeat(32);
        assert!(!verify_inclusion(&leaf, &[], &"cc".repeat(32)).unwrap());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_false_negative() {
        assert_eq!(
            verify_inclusion("zz", &[], &"aa".repeat(32)).unwrap_err(),
            MerkleError::BadLeafHex("zz".into())
        );
        assert_eq!(
            verify_inclusion(&"aa".repeat(32), &[step("zz", "left")], &"aa".repeat(32))
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
                &"aa".repeat(32)
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
}
