//! Offline RFC 3161 TimeStampToken verification.
//!
//! A TimeStampToken is a CMS `SignedData` (RFC 5652) whose encapsulated content
//! is a `TSTInfo` (RFC 3161 §2.4.2). Verifying it offline answers two questions:
//!
//! 1. **What was timestamped?** — `TSTInfo.messageImprint.hashedMessage`, which
//!    must equal the Merkle root the proof claims.
//! 2. **Is the token authentic?** — the `SignerInfo` signature over `signedAttrs`,
//!    checked against the TSA certificate embedded in the token itself.
//!
//! No network access and no API key are required.
//!
//! ## Gotchas this module encodes
//!
//! - The signature covers the DER `SET OF` encoding of `signedAttrs`. On the
//!   wire that field is `[0] IMPLICIT`, so the leading tag byte must be
//!   rewritten from `0xA0` to `0x31` before verifying.
//! - For ECDSA the digest is chosen by the **signatureAlgorithm OID**
//!   (e.g. `ecdsa-with-SHA512`), *not* by `SignerInfo.digestAlgorithm`. Real SK
//!   ID Solutions tokens use SHA-256 for the messageImprint, SHA-512 for the
//!   SignerInfo digest, and ecdsa-with-SHA512 over a P-256 key — three
//!   different algorithm slots that must not be conflated.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::{Decode, Encode, Reader};
use sha2::{Digest, Sha256, Sha512};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::merkle::hex_encode;

// Digest algorithms
const ID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const ID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const ID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
// CMS attributes
const ID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
// Public key algorithms
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const ID_RSA: &str = "1.2.840.113549.1.1.1";
// ECDSA signature algorithms
const ID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const ID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const ID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
// Named curves
const ID_SECP256R1: &str = "1.2.840.10045.3.1.7";
const ID_SECP384R1: &str = "1.3.132.0.34";

/// What a token says, once parsed and cryptographically checked.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// Hex of `messageImprint.hashedMessage` — what the TSA actually signed.
    pub message_imprint: String,
    /// OID of the imprint hash algorithm.
    pub imprint_algorithm: String,
    /// TSA token serial number, decimal.
    pub serial_number: String,
    /// `genTime` as Unix seconds.
    pub gen_time_unix: i64,
    /// Distinguished name of the signing TSA certificate.
    pub signer_subject: String,
    /// True if the SignerInfo signature verified against the embedded certificate.
    pub signature_valid: bool,
}

#[derive(Debug)]
pub enum TokenError {
    Malformed(String),
    Unsupported(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed timestamp token: {m}"),
            Self::Unsupported(m) => write!(f, "unsupported timestamp token: {m}"),
        }
    }
}

impl std::error::Error for TokenError {}

fn malformed<T: std::fmt::Display>(e: T) -> TokenError {
    TokenError::Malformed(e.to_string())
}

fn digest_by_oid(oid: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    match oid {
        ID_SHA256 => Some(Sha256::digest(bytes).to_vec()),
        ID_SHA384 => Some(sha2::Sha384::digest(bytes).to_vec()),
        ID_SHA512 => Some(Sha512::digest(bytes).to_vec()),
        _ => None,
    }
}

/// Human name for a digest OID, for display only.
pub fn digest_name(oid: &str) -> &str {
    match oid {
        ID_SHA256 => "SHA-256",
        ID_SHA384 => "SHA-384",
        ID_SHA512 => "SHA-512",
        other => other,
    }
}

/// Parses a DER-encoded RFC 3161 TimeStampToken and verifies its signature.
pub fn inspect(token_der: &[u8]) -> Result<TokenInfo, TokenError> {
    let ci = ContentInfo::from_der(token_der).map_err(malformed)?;
    let sd: SignedData = ci.content.decode_as().map_err(malformed)?;

    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| TokenError::Malformed("SignedData has no eContent".into()))?;
    let tst_der = econtent.value();

    let tst = parse_tst_info(tst_der)?;

    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| TokenError::Malformed("SignedData has no SignerInfo".into()))?;

    let signer_cert = find_signer_cert(&sd)
        .ok_or_else(|| TokenError::Malformed("no signer certificate embedded in token".into()))?;

    let signature_valid = verify_signer(si, tst_der, &signer_cert)?;

    Ok(TokenInfo {
        message_imprint: tst.imprint,
        imprint_algorithm: tst.imprint_alg,
        serial_number: tst.serial,
        gen_time_unix: tst.gen_time_unix,
        signer_subject: signer_cert.tbs_certificate.subject.to_string(),
        signature_valid,
    })
}

struct TstInfo {
    imprint: String,
    imprint_alg: String,
    serial: String,
    gen_time_unix: i64,
}

/// ```text
/// TSTInfo ::= SEQUENCE {
///   version        INTEGER,
///   policy         OBJECT IDENTIFIER,
///   messageImprint SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING },
///   serialNumber   INTEGER,
///   genTime        GeneralizedTime,
///   ... }
/// ```
fn parse_tst_info(tst_der: &[u8]) -> Result<TstInfo, TokenError> {
    let mut r = der::SliceReader::new(tst_der).map_err(malformed)?;
    let _seq = der::Header::decode(&mut r).map_err(malformed)?;
    let _version = der::asn1::Int::decode(&mut r).map_err(malformed)?;
    let _policy = der::asn1::ObjectIdentifier::decode(&mut r).map_err(malformed)?;

    // messageImprint
    let _mi = der::Header::decode(&mut r).map_err(malformed)?;
    let alg_hdr = der::Header::decode(&mut r).map_err(malformed)?;
    let hash_oid = der::asn1::ObjectIdentifier::decode(&mut r).map_err(malformed)?;
    // AlgorithmIdentifier.parameters is optional and usually an explicit NULL
    if alg_hdr.length > hash_oid.encoded_len().map_err(malformed)? {
        let _ = der::asn1::Null::decode(&mut r);
    }
    let hashed = der::asn1::OctetString::decode(&mut r).map_err(malformed)?;

    let serial = der::asn1::Int::decode(&mut r).map_err(malformed)?;
    let gen_time_unix = decode_gen_time(&mut r)?;

    Ok(TstInfo {
        imprint: hex_encode(hashed.as_bytes()),
        imprint_alg: hash_oid.to_string(),
        serial: int_to_decimal(serial.as_bytes()),
        gen_time_unix,
    })
}

/// Decodes `TSTInfo.genTime`, tolerating the fractional seconds RFC 3161 allows.
///
/// `der::asn1::GeneralizedTime` enforces the X.509 profile (RFC 5280 §4.1.2.5.2),
/// which pins the encoding to exactly `YYYYMMDDHHMMSSZ` and rejects a fraction.
/// RFC 3161 §2.4.2 is deliberately looser — genTime pairs with the `accuracy`
/// field, and a TSA may express sub-second precision. EuroCert does exactly that
/// (`20260904160723.776Z`), so decoding a real qualified token through the strict
/// type failed outright and the CLI reported PROOF INVALID for a perfectly valid
/// timestamp. SK ID Solutions emits whole seconds, which is why this went unseen.
///
/// The fraction is parsed for validity and then dropped: [`TstInfo`] reports whole
/// seconds, and no verification decision depends on milliseconds.
fn decode_gen_time(r: &mut der::SliceReader<'_>) -> Result<i64, TokenError> {
    let header = der::Header::decode(r).map_err(malformed)?;
    if header.tag != der::Tag::GeneralizedTime {
        return Err(TokenError::Malformed(format!(
            "expected genTime GeneralizedTime, found {}",
            header.tag
        )));
    }
    let bytes = r.read_slice(header.length).map_err(malformed)?;
    parse_generalized_time(bytes)
}

/// Parses an ASN.1 `GeneralizedTime` body into Unix seconds.
///
/// Accepts `YYYYMMDDHHMMSSZ` and `YYYYMMDDHHMMSS.fffZ` (ASN.1 permits `,` as the
/// decimal separator too). Offsets other than `Z` are refused rather than guessed
/// at: RFC 3161 §2.4.2 requires genTime in UTC, so a local-time token is a token
/// we do not understand, not one we should silently reinterpret.
fn parse_generalized_time(bytes: &[u8]) -> Result<i64, TokenError> {
    let text = core::str::from_utf8(bytes)
        .map_err(|_| TokenError::Malformed("genTime is not valid ASCII".into()))?;

    let body = text.strip_suffix('Z').ok_or_else(|| {
        TokenError::Malformed(format!("genTime {text:?} is not UTC (must end in 'Z')"))
    })?;

    let (whole, fraction) = match body.split_once(['.', ',']) {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };

    if whole.len() != 14 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TokenError::Malformed(format!(
            "genTime {text:?} is not YYYYMMDDHHMMSS[.fff]Z"
        )));
    }
    if let Some(f) = fraction {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return Err(TokenError::Malformed(format!(
                "genTime {text:?} has a malformed fractional part"
            )));
        }
    }

    let field = |a: usize, b: usize| whole[a..b].parse::<u32>().unwrap_or(0);
    let date = der::DateTime::new(
        field(0, 4) as u16,
        field(4, 6) as u8,
        field(6, 8) as u8,
        field(8, 10) as u8,
        field(10, 12) as u8,
        field(12, 14) as u8,
    )
    .map_err(|_| TokenError::Malformed(format!("genTime {text:?} is not a real date")))?;

    Ok(date.unix_duration().as_secs() as i64)
}

/// Renders a big-endian unsigned INTEGER as a decimal string without pulling in
/// a bignum dependency — TSA serials routinely exceed u64.
fn int_to_decimal(be_bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in be_bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn find_signer_cert(sd: &SignedData) -> Option<Certificate> {
    let certs = sd.certificates.as_ref()?;
    let mut candidates: Vec<&Certificate> = Vec::new();
    for choice in certs.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            candidates.push(cert);
        }
    }
    // Prefer the certificate carrying the id-kp-timeStamping EKU (1.3.6.1.5.5.7.3.8);
    // a token may embed the whole chain, and only the leaf signs.
    candidates
        .iter()
        .find(|c| has_timestamping_eku(c))
        .or_else(|| candidates.first())
        .map(|c| (*c).clone())
}

fn has_timestamping_eku(cert: &Certificate) -> bool {
    const ID_KP_TIMESTAMPING: &str = "1.3.6.1.5.5.7.3.8";
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    exts.iter().any(|ext| {
        ext.extn_id.to_string() == "2.5.29.37"
            && der::asn1::SequenceOf::<der::asn1::ObjectIdentifier, 16>::from_der(
                ext.extn_value.as_bytes(),
            )
            .map(|oids| oids.iter().any(|o| o.to_string() == ID_KP_TIMESTAMPING))
            .unwrap_or(false)
    })
}

fn verify_signer(si: &SignerInfo, econtent: &[u8], cert: &Certificate) -> Result<bool, TokenError> {
    let digest_oid = si.digest_alg.oid.to_string();
    let sig_oid = si.signature_algorithm.oid.to_string();

    let signed_attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TokenError::Malformed("SignerInfo has no signedAttrs".into()))?;

    // The messageDigest attribute must bind signedAttrs to the eContent, otherwise
    // a valid signature over unrelated attributes would "verify" a forged TSTInfo.
    let expected = digest_by_oid(&digest_oid, econtent)
        .ok_or_else(|| TokenError::Unsupported(format!("digest algorithm {digest_oid}")))?;
    let mut digest_bound = false;
    for attr in signed_attrs.iter() {
        if attr.oid.to_string() == ID_MESSAGE_DIGEST {
            let v = attr
                .values
                .as_slice()
                .first()
                .ok_or_else(|| TokenError::Malformed("empty messageDigest attribute".into()))?;
            let der_bytes = v.to_der().map_err(malformed)?;
            let got = der::asn1::OctetString::from_der(&der_bytes).map_err(malformed)?;
            digest_bound = crate::merkle::constant_time_eq(got.as_bytes(), &expected);
        }
    }
    if !digest_bound {
        return Ok(false);
    }

    // Signature covers the DER SET OF signedAttrs; rewrite [0] IMPLICIT -> SET.
    let mut tbs = signed_attrs.to_der().map_err(malformed)?;
    if tbs.is_empty() {
        return Err(TokenError::Malformed("empty signedAttrs encoding".into()));
    }
    tbs[0] = 0x31;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    match spki.algorithm.oid.to_string().as_str() {
        ID_EC_PUBLIC_KEY => verify_ecdsa(spki, &tbs, si.signature.as_bytes(), &sig_oid),
        ID_RSA => verify_rsa(spki, &tbs, si.signature.as_bytes(), &digest_oid),
        other => Err(TokenError::Unsupported(format!("key algorithm {other}"))),
    }
}

fn verify_ecdsa(
    spki: &SubjectPublicKeyInfoOwned,
    tbs: &[u8],
    sig: &[u8],
    sig_oid: &str,
) -> Result<bool, TokenError> {
    use signature::hazmat::PrehashVerifier;

    // ECDSA signs a prehash whose algorithm comes from the *signature* OID.
    let prehash = match sig_oid {
        ID_ECDSA_SHA256 => Sha256::digest(tbs).to_vec(),
        ID_ECDSA_SHA384 => sha2::Sha384::digest(tbs).to_vec(),
        ID_ECDSA_SHA512 => Sha512::digest(tbs).to_vec(),
        other => return Err(TokenError::Unsupported(format!("ECDSA algorithm {other}"))),
    };

    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
        .map(|o| o.to_string())
        .unwrap_or_default();

    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| TokenError::Malformed("public key is not byte-aligned".into()))?;

    match curve_oid.as_str() {
        ID_SECP256R1 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(malformed)?;
            let der_sig = p256::ecdsa::DerSignature::try_from(sig).map_err(malformed)?;
            let signature: p256::ecdsa::Signature = der_sig.try_into().map_err(malformed)?;
            Ok(vk.verify_prehash(&prehash, &signature).is_ok())
        }
        ID_SECP384R1 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes).map_err(malformed)?;
            let der_sig = p384::ecdsa::DerSignature::try_from(sig).map_err(malformed)?;
            let signature: p384::ecdsa::Signature = der_sig.try_into().map_err(malformed)?;
            Ok(vk.verify_prehash(&prehash, &signature).is_ok())
        }
        other => Err(TokenError::Unsupported(format!("named curve {other}"))),
    }
}

fn verify_rsa(
    spki: &SubjectPublicKeyInfoOwned,
    tbs: &[u8],
    sig: &[u8],
    digest_oid: &str,
) -> Result<bool, TokenError> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;
    use signature::Verifier;

    let spki_der = spki.to_der().map_err(malformed)?;
    let pk = RsaPublicKey::from_public_key_der(&spki_der).map_err(malformed)?;
    let signature = Signature::try_from(sig).map_err(malformed)?;

    Ok(match digest_oid {
        ID_SHA256 => VerifyingKey::<Sha256>::new(pk)
            .verify(tbs, &signature)
            .is_ok(),
        ID_SHA384 => VerifyingKey::<sha2::Sha384>::new(pk)
            .verify(tbs, &signature)
            .is_ok(),
        ID_SHA512 => VerifyingKey::<Sha512>::new(pk)
            .verify(tbs, &signature)
            .is_ok(),
        other => return Err(TokenError::Unsupported(format!("digest algorithm {other}"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_conversion_handles_values_wider_than_u64() {
        assert_eq!(int_to_decimal(&[0x00]), "0");
        assert_eq!(int_to_decimal(&[0x01]), "1");
        assert_eq!(int_to_decimal(&[0xff]), "255");
        assert_eq!(
            int_to_decimal(&[0x66, 0x90, 0x97, 0x4a, 0xbd, 0x36, 0xb3, 0x02]),
            "7390573335772836610"
        );
        // 9 bytes — beyond u64::MAX
        assert_eq!(
            int_to_decimal(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            "18446744073709551616"
        );
    }

    #[test]
    fn garbage_is_rejected_as_malformed() {
        let err = inspect(b"not a token at all").unwrap_err();
        assert!(matches!(err, TokenError::Malformed(_)));
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(inspect(&[]).is_err());
    }

    #[test]
    fn digest_names_are_human_readable() {
        assert_eq!(digest_name(ID_SHA256), "SHA-256");
        assert_eq!(digest_name(ID_SHA512), "SHA-512");
        assert_eq!(digest_name("1.2.3"), "1.2.3");
    }

    // ── genTime parsing ─────────────────────────────────────────────────────
    //
    // RFC 3161 §2.4.2 permits a fractional part on genTime; RFC 5280 §4.1.2.5.2
    // (the X.509 profile the `der` GeneralizedTime type enforces) does not. A
    // qualified TSA is entitled to either, and 0.2.0 only handled one of them.

    #[test]
    fn gen_time_accepts_whole_seconds() {
        // SK ID Solutions' encoding.
        let t = parse_generalized_time(b"20260404075348Z").unwrap();
        assert_eq!(t, 1775289228);
    }

    #[test]
    fn gen_time_accepts_fractional_seconds() {
        // EuroCert's encoding — the case that shipped broken in 0.2.0.
        let whole = parse_generalized_time(b"20260904160723Z").unwrap();
        let frac = parse_generalized_time(b"20260904160723.776Z").unwrap();
        assert_eq!(frac, whole, "the fraction must be dropped, not rounded");
        assert_eq!(frac, 1788538043);
    }

    #[test]
    fn gen_time_accepts_a_comma_as_the_decimal_separator() {
        // ASN.1 allows either separator; some TSAs emit a comma.
        assert_eq!(
            parse_generalized_time(b"20260904160723,776Z").unwrap(),
            parse_generalized_time(b"20260904160723.776Z").unwrap()
        );
    }

    #[test]
    fn gen_time_accepts_any_fraction_length() {
        for s in [
            &b"20260904160723.7Z"[..],
            &b"20260904160723.77Z"[..],
            &b"20260904160723.776999Z"[..],
        ] {
            assert_eq!(parse_generalized_time(s).unwrap(), 1788538043);
        }
    }

    #[test]
    fn gen_time_refuses_non_utc() {
        // RFC 3161 requires UTC. A local-time token is one we do not understand,
        // not one to silently reinterpret as UTC.
        assert!(parse_generalized_time(b"20260904160723+0200").is_err());
        assert!(parse_generalized_time(b"20260904160723").is_err());
    }

    #[test]
    fn gen_time_refuses_a_malformed_fraction() {
        assert!(parse_generalized_time(b"20260904160723.Z").is_err());
        assert!(parse_generalized_time(b"20260904160723.abcZ").is_err());
    }

    #[test]
    fn gen_time_refuses_a_wrong_length_or_non_digits() {
        assert!(parse_generalized_time(b"202609041607Z").is_err());
        assert!(parse_generalized_time(b"2026090416072xZ").is_err());
        assert!(parse_generalized_time(b"").is_err());
    }

    #[test]
    fn gen_time_refuses_an_impossible_date() {
        assert!(parse_generalized_time(b"20261304160723Z").is_err()); // month 13
        assert!(parse_generalized_time(b"20260932160723Z").is_err()); // day 32
    }
}
