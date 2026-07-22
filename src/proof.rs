//! The proof bundle as served by `GET /v1/anchor/{id}/proof` and written to
//! disk by `trustbeat anchor --wait`.
//!
//! Field names mirror `docs/MANUAL_VERIFICATION.md` — a bundle written by the
//! CLI must stay readable by the portal, the SDKs and the manual openssl route.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: String,
    /// Position of the *sibling*: "left" or "right".
    pub side: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(default)]
    pub id: String,
    /// SHA-256 of the anchored content, hex.
    pub hash: String,
    #[serde(default)]
    pub hash_algorithm: String,
    #[serde(default)]
    pub batch_id: String,
    #[serde(default)]
    pub leaf_index: u64,
    /// Root of the Merkle batch that was timestamped, hex.
    #[serde(default)]
    pub merkle_root: String,
    #[serde(default)]
    pub proof_path: Vec<ProofStep>,
    /// RFC 3161 TimeStampToken, base64-encoded DER.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub token_format: String,
    #[serde(default)]
    pub tsa_serial: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub anchored_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archive_stamps: Vec<serde_json::Value>,
}

impl Proof {
    /// A proof is only complete once the batch has been anchored; until then the
    /// API returns the job with an empty merkle_root.
    pub fn is_pending(&self) -> bool {
        self.merkle_root.is_empty() || self.token.is_empty()
    }
}

/// The job returned by `POST /v1/anchor` before the batch is anchored.
/// `hash` and `status` are echoed by the API and kept here to document the wire
/// shape even though the CLI only needs `id`.
#[derive(Debug, Clone, Deserialize)]
pub struct AnchorJob {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub hash: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = include_str!("../tests/fixtures/demo-proof.json");

    #[test]
    fn parses_a_real_proof_bundle() {
        let p: Proof = serde_json::from_str(DEMO).unwrap();
        assert_eq!(p.hash_algorithm, "SHA-256");
        assert_eq!(p.tsa_serial, "7390573335772836610");
        assert!(p.provider.contains("SK ID Solutions"));
        assert!(!p.is_pending());
    }

    #[test]
    fn round_trips_through_serde_without_losing_fields() {
        let p: Proof = serde_json::from_str(DEMO).unwrap();
        let written = serde_json::to_string(&p).unwrap();
        let again: Proof = serde_json::from_str(&written).unwrap();
        assert_eq!(again.hash, p.hash);
        assert_eq!(again.merkle_root, p.merkle_root);
        assert_eq!(again.token, p.token);
        assert_eq!(again.proof_path, p.proof_path);
    }

    #[test]
    fn a_job_without_a_root_is_pending() {
        let pending: Proof = serde_json::from_str(r#"{"hash":"ab"}"#).unwrap();
        assert!(pending.is_pending());
    }

    #[test]
    fn unknown_fields_do_not_break_parsing() {
        // The API may add fields; an old CLI must keep working.
        let p: Proof =
            serde_json::from_str(r#"{"hash":"ab","future_field":{"nested":1}}"#).unwrap();
        assert_eq!(p.hash, "ab");
    }
}
