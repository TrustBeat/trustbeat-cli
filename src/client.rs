//! Thin blocking HTTP client for the TrustBeat API.
//!
//! Only the two endpoints the CLI needs:
//!   `POST /anchor`            → submit a hash, get a tracking id
//!   `GET  /anchor/{id}/proof` → fetch the inclusion proof once anchored

use std::time::{Duration, Instant};

use crate::proof::{AnchorJob, Proof};

pub struct Client {
    api_key: String,
    base_url: String,
    agent: ureq::Agent,
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    RateLimited,
    Status { code: u16, message: String },
    Transport(String),
    Decode(String),
    Timeout(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(
                f,
                "API key rejected (401). Check TRUSTBEAT_API_KEY, or get a key at https://trustbeat.eu/register"
            ),
            Self::RateLimited => write!(f, "rate limited (429) — retry shortly or upgrade your plan"),
            Self::Status { code, message } => write!(f, "API returned {code}: {message}"),
            Self::Transport(m) => write!(f, "network error: {m}"),
            Self::Decode(m) => write!(f, "could not parse API response: {m}"),
            Self::Timeout(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl Client {
    pub fn new(api_key: String, base_url: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .user_agent(concat!("trustbeat-cli/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            api_key,
            base_url,
            agent,
        }
    }

    /// Submits a SHA-256 hash for anchoring. Returns immediately with a job id —
    /// the batch is anchored on the next cycle.
    pub fn anchor(
        &self,
        hash: &str,
        client_ref: Option<&str>,
        description: Option<&str>,
    ) -> Result<AnchorJob, ApiError> {
        let mut body = serde_json::json!({
            "hash": hash,
            "hash_algorithm": "SHA-256",
        });
        if let Some(r) = client_ref {
            body["client_ref"] = serde_json::Value::String(r.to_string());
        }
        if let Some(d) = description {
            body["description"] = serde_json::Value::String(d.to_string());
        }

        let resp = self
            .agent
            .post(&format!("{}/anchor", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .send_json(body);

        let value: serde_json::Value = handle(resp)?;
        serde_json::from_value(value).map_err(|e| ApiError::Decode(e.to_string()))
    }

    /// Fetches the proof for a tracking id. `Ok(None)` means "not anchored yet".
    pub fn get_proof(&self, tracking_id: &str) -> Result<Option<Proof>, ApiError> {
        let resp = self
            .agent
            .get(&format!(
                "{}/anchor/{}/proof",
                self.base_url,
                urlencode(tracking_id)
            ))
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .call();

        let value: serde_json::Value = handle(resp)?;
        let proof: Proof =
            serde_json::from_value(value).map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok(if proof.is_pending() {
            None
        } else {
            Some(proof)
        })
    }

    /// Polls until the proof is ready. Calls `on_tick` before each sleep so the
    /// caller can show progress.
    pub fn wait_for_proof(
        &self,
        tracking_id: &str,
        timeout: Duration,
        poll: Duration,
        mut on_tick: impl FnMut(Duration),
    ) -> Result<Proof, ApiError> {
        let started = Instant::now();
        loop {
            if let Some(proof) = self.get_proof(tracking_id)? {
                return Ok(proof);
            }
            let elapsed = started.elapsed();
            if elapsed + poll > timeout {
                return Err(ApiError::Timeout(format!(
                    "proof not ready after {}s. The anchor is still queued — \
                     retry with:\n  trustbeat proof {tracking_id}",
                    timeout.as_secs()
                )));
            }
            on_tick(elapsed);
            std::thread::sleep(poll);
        }
    }
}

fn handle(resp: Result<ureq::Response, ureq::Error>) -> Result<serde_json::Value, ApiError> {
    match resp {
        Ok(r) => r
            .into_json::<serde_json::Value>()
            .map_err(|e| ApiError::Decode(e.to_string())),
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            Err(ApiError::Unauthorized)
        }
        Err(ureq::Error::Status(429, _)) => Err(ApiError::RateLimited),
        Err(ureq::Error::Status(code, r)) => {
            let message = r
                .into_json::<serde_json::Value>()
                .ok()
                .and_then(|v| {
                    v.get("message")
                        .or_else(|| v.get("error"))
                        .and_then(|m| m.as_str().map(String::from))
                })
                .unwrap_or_else(|| "no details".into());
            Err(ApiError::Status { code, message })
        }
        Err(ureq::Error::Transport(t)) => Err(ApiError::Transport(t.to_string())),
    }
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => other
                .to_string()
                .bytes()
                .map(|b| format!("%{b:02X}"))
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_are_escaped() {
        assert_eq!(
            urlencode("01KNBQMYC0AQ7KA561TNKK71GJ"),
            "01KNBQMYC0AQ7KA561TNKK71GJ"
        );
        assert_eq!(urlencode("a/../b"), "a%2F..%2Fb");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("ü"), "%C3%BC");
    }

    #[test]
    fn errors_explain_themselves() {
        assert!(ApiError::Unauthorized.to_string().contains("401"));
        assert!(ApiError::RateLimited.to_string().contains("429"));
        assert!(ApiError::Status {
            code: 500,
            message: "boom".into()
        }
        .to_string()
        .contains("boom"));
    }
}
