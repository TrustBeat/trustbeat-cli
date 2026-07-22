//! Streaming SHA-256 of local files.
//!
//! Files are hashed in fixed-size chunks and never held in memory in full, and
//! never leave the machine — the CLI only ever transmits the resulting digest.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::merkle::hex_encode;

const CHUNK: usize = 64 * 1024;

/// Returns the lowercase hex SHA-256 of a file's contents.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(CHUNK, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

/// Validates a user-supplied hash: exactly 64 lowercase-able hex characters.
pub fn normalize_sha256_hex(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "expected a 64-character SHA-256 hex digest, got {} characters",
            trimmed.len()
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hash contains non-hexadecimal characters".into());
    }
    Ok(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(contents: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "trustbeat-hash-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn hashes_an_empty_file_to_the_known_sha256() {
        let p = temp_file(b"");
        assert_eq!(
            hash_file(&p).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn hashes_known_content() {
        let p = temp_file(b"abc");
        assert_eq!(
            hash_file(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn chunk_boundaries_do_not_change_the_digest() {
        // Larger than one 64 KiB chunk, so the streaming path is exercised.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let p = temp_file(&data);
        let streamed = hash_file(&p).unwrap();
        let oneshot = hex_encode(&Sha256::digest(&data));
        assert_eq!(streamed, oneshot);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn missing_file_is_an_io_error() {
        assert!(hash_file(Path::new("/nonexistent/trustbeat/file")).is_err());
    }

    #[test]
    fn accepts_and_lowercases_a_valid_digest() {
        let upper = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        assert_eq!(
            normalize_sha256_hex(upper).unwrap(),
            upper.to_ascii_lowercase()
        );
        assert!(
            normalize_sha256_hex("   ").is_err(),
            "blank input is not a digest"
        );
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        assert!(normalize_sha256_hex("abc").is_err());
        assert!(normalize_sha256_hex(&"a".repeat(63)).is_err());
        assert!(normalize_sha256_hex(&"a".repeat(65)).is_err());
        assert!(normalize_sha256_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(normalize_sha256_hex(&format!("  {h}\n")).unwrap(), h);
    }
}
