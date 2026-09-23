//! Thin blocking HTTP client for the TrustBeat API.
//!
//! Only the two endpoints the CLI needs:
//!   `POST /anchor`            → submit a hash, get a tracking id
//!   `GET  /anchor/{id}/proof` → fetch the inclusion proof once anchored

use std::time::{Duration, Instant};

use crate::proof::{AnchorJob, Proof};

/// How many times a rate-limited (HTTP 429) request is retried. Only 429: the API refuses a
/// rate-limited submission before queuing it, so a retry can never anchor a hash twice.
const MAX_RETRIES: u32 = 2;

/// A 429 asking to wait longer than this is reported at once rather than waited out.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(60);

pub struct Client {
    api_key: String,
    base_url: String,
    agent: ureq::Agent,
    max_retries: u32,
    /// How the client waits between 429 retries. Replaced in tests.
    sleep: fn(Duration),
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    /// Still rate-limited after the automatic retries. `retry_after` is the wait the server asked for.
    RateLimited {
        retry_after: Option<Duration>,
    },
    Status {
        code: u16,
        message: String,
        /// `error.request_id` from the API envelope — quote it when reporting a bug.
        request_id: Option<String>,
    },
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
            Self::RateLimited { retry_after } => match retry_after {
                Some(d) => write!(
                    f,
                    "rate limited (429) — retry in {} s, or upgrade your plan",
                    d.as_secs().max(1)
                ),
                None => write!(f, "rate limited (429) — retry shortly or upgrade your plan"),
            },
            Self::Status {
                code,
                message,
                request_id,
            } => {
                write!(f, "API returned {code}: {message}")?;
                match request_id {
                    Some(id) => write!(f, " (request id: {id})"),
                    None => Ok(()),
                }
            }
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
            max_retries: MAX_RETRIES,
            sleep: std::thread::sleep,
        }
    }

    /// Sends a request, retrying HTTP 429 up to `max_retries` times on the server's `Retry-After`
    /// (1 s, 2 s … when it sends none). Every other outcome goes straight to [`handle`].
    fn send(
        &self,
        // Boxed: ureq::Error is large, and clippy rejects closures returning it unboxed.
        request: impl Fn() -> Result<ureq::Response, Box<ureq::Error>>,
    ) -> Result<serde_json::Value, ApiError> {
        let mut attempt = 0;
        loop {
            match request().map_err(|e| *e) {
                Err(ureq::Error::Status(429, r)) => {
                    let asked = retry_after(&r);
                    let wait = asked.unwrap_or(Duration::from_secs(1 << attempt));
                    if attempt >= self.max_retries || wait > MAX_RETRY_WAIT {
                        return Err(ApiError::RateLimited { retry_after: asked });
                    }
                    (self.sleep)(wait);
                    attempt += 1;
                }
                other => return handle(other),
            }
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

        let value = self.send(|| {
            self.agent
                .post(&format!("{}/anchor", self.base_url))
                .set("Authorization", &format!("Bearer {}", self.api_key))
                .send_json(body.clone())
                .map_err(Box::new)
        })?;
        serde_json::from_value(value).map_err(|e| ApiError::Decode(e.to_string()))
    }

    /// Fetches the proof for a tracking id. `Ok(None)` means "not anchored yet".
    pub fn get_proof(&self, tracking_id: &str) -> Result<Option<Proof>, ApiError> {
        let value = self.send(|| {
            self.agent
                .get(&format!(
                    "{}/anchor/{}/proof",
                    self.base_url,
                    urlencode(tracking_id)
                ))
                .set("Authorization", &format!("Bearer {}", self.api_key))
                .call()
                .map_err(Box::new)
        })?;
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
        Err(ureq::Error::Status(429, r)) => Err(ApiError::RateLimited {
            retry_after: retry_after(&r),
        }),
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_json::<serde_json::Value>().ok();
            let (message, request_id) = match &body {
                Some(v) => (extract_message(v), extract_request_id(v)),
                None => (None, None),
            };
            Err(ApiError::Status {
                code,
                message: message.unwrap_or_else(|| "no details".into()),
                request_id,
            })
        }
        Err(ureq::Error::Transport(t)) => Err(ApiError::Transport(t.to_string())),
    }
}

/// The `Retry-After` header as a duration, or `None` when absent or not a number of seconds.
/// TrustBeat sends whole seconds; the HTTP-date form is not used, so it falls back to backoff.
fn retry_after(r: &ureq::Response) -> Option<Duration> {
    let secs: f64 = r.header("Retry-After")?.trim().parse().ok()?;
    (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs))
}

/// Pulls the human-readable message out of an API error body.
///
/// The API's envelope is `{"error": {"code", "message", "request_id"}}` — the
/// message lives one level down. Flat `message` / `error` strings are also
/// accepted so a proxy or a future shape still yields something readable.
fn extract_message(v: &serde_json::Value) -> Option<String> {
    v.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| v.get("message").and_then(|m| m.as_str()))
        .or_else(|| v.get("error").and_then(|e| e.as_str()))
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn extract_request_id(v: &serde_json::Value) -> Option<String> {
    v.get("error")
        .and_then(|e| e.get("request_id"))
        .and_then(|m| m.as_str())
        .or_else(|| v.get("request_id").and_then(|m| m.as_str()))
        .map(str::to_string)
        .filter(|s| !s.is_empty())
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
        assert!(ApiError::RateLimited { retry_after: None }
            .to_string()
            .contains("429"));
        assert!(ApiError::RateLimited {
            retry_after: Some(Duration::from_secs(7))
        }
        .to_string()
        .contains("retry in 7 s"));
        assert!(ApiError::Status {
            code: 500,
            message: "boom".into(),
            request_id: None,
        }
        .to_string()
        .contains("boom"));
    }

    #[test]
    fn a_status_error_quotes_the_request_id_when_there_is_one() {
        let rendered = ApiError::Status {
            code: 404,
            message: "Tracking ID not found.".into(),
            request_id: Some("req_01KZ1095C1K2H0Q9PFBYW15SNY".into()),
        }
        .to_string();
        assert!(rendered.contains("Tracking ID not found."));
        assert!(rendered.contains("req_01KZ1095C1K2H0Q9PFBYW15SNY"));
    }

    /// Verbatim body from production, 2026-08-02.
    #[test]
    fn reads_the_nested_error_envelope_the_api_actually_sends() {
        let body: serde_json::Value = serde_json::from_str(
            r#"{"error":{"code":"NOT_FOUND","message":"Tracking ID not found.",
                "request_id":"req_01KZ1095C1K2H0Q9PFBYW15SNY"}}"#,
        )
        .unwrap();
        assert_eq!(
            extract_message(&body).as_deref(),
            Some("Tracking ID not found.")
        );
        assert_eq!(
            extract_request_id(&body).as_deref(),
            Some("req_01KZ1095C1K2H0Q9PFBYW15SNY")
        );
    }

    #[test]
    fn falls_back_to_flat_shapes() {
        let flat_message: serde_json::Value = serde_json::json!({"message": "plain"});
        assert_eq!(extract_message(&flat_message).as_deref(), Some("plain"));

        let flat_error: serde_json::Value = serde_json::json!({"error": "just a string"});
        assert_eq!(
            extract_message(&flat_error).as_deref(),
            Some("just a string")
        );
    }

    #[test]
    fn a_body_with_no_usable_message_yields_none() {
        assert_eq!(extract_message(&serde_json::json!({})), None);
        assert_eq!(extract_message(&serde_json::json!({"error": {}})), None);
        assert_eq!(extract_message(&serde_json::json!({"message": ""})), None);
        assert_eq!(extract_request_id(&serde_json::json!({"error": {}})), None);
    }

    // ── 429 retry, against a scripted local HTTP server ─────────────────────────

    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Serves one scripted `(status, retry_after, body)` per connection (the last repeats) and
    /// counts requests. `Connection: close` keeps it to one request per connection.
    fn scripted(
        steps: Vec<(u16, Option<&'static str>, &'static str)>,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let seen = count.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let (status, retry, text) = steps[n.min(steps.len() - 1)];
                let extra = retry
                    .map(|r| format!("Retry-After: {r}\r\n"))
                    .unwrap_or_default();
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                )
                .unwrap();
            }
        });
        (url, count)
    }

    const LIMITED: &str = r#"{"error":{"code":"RATE_LIMITED","message":"Slow down"}}"#;
    const ACCEPTED: &str = r#"{"id":"track-1","hash":"aa","hash_algorithm":"SHA-256","status":"pending","submitted_at":"2026-09-23T10:00:00Z"}"#;

    static WAITS: Mutex<Vec<Duration>> = Mutex::new(Vec::new());
    static WAITS_LOCK: Mutex<()> = Mutex::new(());

    fn record(d: Duration) {
        WAITS.lock().unwrap().push(d);
    }

    /// A client that records its waits instead of sleeping. Tests using it hold `WAITS_LOCK`,
    /// because the recorder is a plain `fn` and so shares one global list.
    fn recording(url: &str, max_retries: u32) -> Client {
        WAITS.lock().unwrap().clear();
        Client {
            max_retries,
            sleep: record,
            ..Client::new("tb_live_test".into(), url.into())
        }
    }

    fn waits() -> Vec<Duration> {
        WAITS.lock().unwrap().clone()
    }

    #[test]
    fn a_429_is_retried_after_retry_after() {
        let _g = WAITS_LOCK.lock().unwrap();
        let (url, count) = scripted(vec![(429, Some("3"), LIMITED), (202, None, ACCEPTED)]);
        let job = recording(&url, 2)
            .anchor(&"a".repeat(64), None, None)
            .unwrap();
        assert_eq!(job.id, "track-1");
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(waits(), vec![Duration::from_secs(3)]);
    }

    #[test]
    fn gives_up_after_the_retries_with_the_servers_wait() {
        let _g = WAITS_LOCK.lock().unwrap();
        let (url, count) = scripted(vec![(429, Some("2"), LIMITED)]);
        let err = recording(&url, 2)
            .anchor(&"a".repeat(64), None, None)
            .unwrap_err();
        assert!(
            matches!(err, ApiError::RateLimited { retry_after: Some(d) } if d == Duration::from_secs(2))
        );
        assert_eq!(count.load(Ordering::SeqCst), 3);
        assert_eq!(waits().len(), 2);
    }

    #[test]
    fn backs_off_without_retry_after() {
        let _g = WAITS_LOCK.lock().unwrap();
        let (url, _) = scripted(vec![
            (429, None, LIMITED),
            (429, None, LIMITED),
            (202, None, ACCEPTED),
        ]);
        recording(&url, 2)
            .anchor(&"a".repeat(64), None, None)
            .unwrap();
        assert_eq!(
            waits(),
            vec![Duration::from_secs(1), Duration::from_secs(2)]
        );
    }

    #[test]
    fn a_wait_over_60_s_is_reported_not_waited() {
        let _g = WAITS_LOCK.lock().unwrap();
        let (url, count) = scripted(vec![(429, Some("120"), LIMITED)]);
        let err = recording(&url, 2)
            .anchor(&"a".repeat(64), None, None)
            .unwrap_err();
        assert!(
            matches!(err, ApiError::RateLimited { retry_after: Some(d) } if d == Duration::from_secs(120))
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(waits().is_empty());
    }

    #[test]
    fn other_errors_are_not_retried() {
        // A 5xx may come after the hash was queued; retrying it could anchor it twice.
        let _g = WAITS_LOCK.lock().unwrap();
        let (url, count) = scripted(vec![(503, None, r#"{"error":{"message":"busy"}}"#)]);
        let err = recording(&url, 2)
            .anchor(&"a".repeat(64), None, None)
            .unwrap_err();
        assert!(matches!(err, ApiError::Status { code: 503, .. }));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(waits().is_empty());
    }

    #[test]
    fn proof_polling_is_retried_too() {
        let _g = WAITS_LOCK.lock().unwrap();
        let (url, count) = scripted(vec![(429, Some("1"), LIMITED), (200, None, ACCEPTED)]);
        let proof = recording(&url, 2).get_proof("track-1").unwrap();
        assert!(proof.is_none(), "a pending job is not a proof");
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
