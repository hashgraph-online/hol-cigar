//! Bounded content scanning that runs before atomization or indexing.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cigar_protocol::ContentDigest;
use sha2::{Digest, Sha256};
use std::fmt;

/// Maximum bytes inspected by the built-in scanner for one record.
pub const MAX_SECRET_SCAN_BYTES: usize = 67_108_864;
/// Maximum findings retained for one record.
pub const MAX_SECRET_FINDINGS: usize = 128;

/// Stable built-in secret detector classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecretKind {
    /// PEM private-key material.
    PrivateKey,
    /// AWS-style access-key identifier.
    AwsAccessKey,
    /// GitHub-style personal access token.
    GitHubToken,
    /// Authorization bearer value.
    BearerToken,
    /// Password, secret, or token assignment.
    CredentialAssignment,
    /// High-entropy token-shaped material.
    HighEntropy,
    /// Base64-encoded high-entropy material.
    EncodedSecret,
    /// Organization-configured secret prefix.
    OrganizationPattern,
}

/// One content-free finding with only offsets and detector class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretFinding {
    /// Detector class.
    pub kind: SecretKind,
    /// Inclusive finding byte offset.
    pub start: usize,
    /// Exclusive finding byte offset.
    pub end: usize,
}

/// Fail-closed result from one bounded scan.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretScan {
    findings: Vec<SecretFinding>,
    truncated: bool,
}

impl SecretScan {
    /// Returns retained content-free findings.
    #[must_use]
    pub fn findings(&self) -> &[SecretFinding] {
        &self.findings
    }

    /// Returns whether input or findings exceeded a scanner bound.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Returns true when content must be withheld from atomization and indexing.
    #[must_use]
    pub fn must_quarantine(&self) -> bool {
        self.truncated || !self.findings.is_empty()
    }
}

impl fmt::Debug for SecretScan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretScan")
            .field("finding_count", &self.findings.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Scans bytes using bounded deterministic detectors without formatting content.
#[must_use]
pub fn scan_secrets(bytes: &[u8]) -> SecretScan {
    scan_secrets_with_patterns(bytes, &[])
}

/// Scans with additional bounded organization-specific byte prefixes.
#[must_use]
pub fn scan_secrets_with_patterns(bytes: &[u8], patterns: &[Vec<u8>]) -> SecretScan {
    let truncated = bytes.len() > MAX_SECRET_SCAN_BYTES;
    let inspected = bytes.get(..MAX_SECRET_SCAN_BYTES).unwrap_or(bytes);
    let mut findings = Vec::new();
    let private_key_marker = [b"-----BE".as_slice(), b"GIN PRI", b"VATE KEY-----"].concat();
    scan_literal(
        inspected,
        &private_key_marker,
        SecretKind::PrivateKey,
        &mut findings,
    );
    let aws_prefix = [b"AK".as_slice(), b"IA"].concat();
    scan_prefixed_token(
        inspected,
        &aws_prefix,
        20,
        SecretKind::AwsAccessKey,
        &mut findings,
    );
    for prefix in [b"ghp_".as_slice(), b"github_pat_".as_slice()] {
        scan_token_minimum(
            inspected,
            prefix,
            20,
            SecretKind::GitHubToken,
            &mut findings,
        );
    }
    scan_token_minimum(
        inspected,
        b"Bearer ",
        16,
        SecretKind::BearerToken,
        &mut findings,
    );
    for assignment in [
        b"password=".as_slice(),
        b"passwd=".as_slice(),
        b"secret=".as_slice(),
        b"token=".as_slice(),
        b"api_key=".as_slice(),
    ] {
        scan_assignment(inspected, assignment, &mut findings);
    }
    scan_entropy_tokens(inspected, &mut findings);
    scan_encoded_tokens(inspected, &mut findings);
    let invalid_patterns = patterns.len() > crate::MAX_SECRET_PATTERNS
        || patterns
            .iter()
            .any(|pattern| pattern.len() < 4 || pattern.len() > 256);
    if !invalid_patterns {
        for pattern in patterns {
            scan_literal(
                inspected,
                pattern,
                SecretKind::OrganizationPattern,
                &mut findings,
            );
        }
    }
    findings.sort_by_key(|finding| (finding.start, finding.end, finding.kind));
    findings.dedup();
    if findings.len() > MAX_SECRET_FINDINGS {
        findings.truncate(MAX_SECRET_FINDINGS);
        return SecretScan {
            findings,
            truncated: true,
        };
    }
    SecretScan {
        findings,
        truncated: truncated || invalid_patterns,
    }
}

/// Computes a tenant-keyed blinded fingerprint without retaining or formatting matched bytes.
#[must_use]
pub fn blinded_secret_fingerprint(
    bytes: &[u8],
    finding: &SecretFinding,
    tenant_blinding_key: &[u8; 32],
) -> Option<ContentDigest> {
    let matched = bytes.get(finding.start..finding.end)?;
    let mut hasher = Sha256::new();
    hasher.update(b"CIGAR-SECRET-FINGERPRINT\0v1\0");
    hasher.update(tenant_blinding_key);
    hasher.update([finding.kind as u8]);
    hasher.update(finding.start.to_be_bytes());
    hasher.update(finding.end.to_be_bytes());
    hasher.update(matched);
    let digest = hasher.finalize();
    let mut value = String::with_capacity(68);
    value.push_str("1220");
    use std::fmt::Write as _;
    for byte in digest {
        if write!(&mut value, "{byte:02x}").is_err() {
            return None;
        }
    }
    ContentDigest::new(value).ok()
}

fn scan_literal(bytes: &[u8], needle: &[u8], kind: SecretKind, findings: &mut Vec<SecretFinding>) {
    for start in literal_offsets(bytes, needle) {
        push_finding(findings, kind, start, start.saturating_add(needle.len()));
    }
}

fn scan_prefixed_token(
    bytes: &[u8],
    prefix: &[u8],
    exact_length: usize,
    kind: SecretKind,
    findings: &mut Vec<SecretFinding>,
) {
    for start in literal_offsets(bytes, prefix) {
        let end = start.saturating_add(exact_length);
        if bytes
            .get(start..end)
            .is_some_and(|token| token.iter().all(u8::is_ascii_alphanumeric))
        {
            push_finding(findings, kind, start, end);
        }
    }
}

fn scan_token_minimum(
    bytes: &[u8],
    prefix: &[u8],
    minimum_suffix: usize,
    kind: SecretKind,
    findings: &mut Vec<SecretFinding>,
) {
    for start in literal_offsets(bytes, prefix) {
        let suffix_start = start.saturating_add(prefix.len());
        let suffix_length = bytes
            .get(suffix_start..)
            .map(|suffix| {
                suffix
                    .iter()
                    .take_while(|byte| is_token_byte(**byte))
                    .count()
            })
            .unwrap_or_default();
        if suffix_length >= minimum_suffix {
            push_finding(
                findings,
                kind,
                start,
                suffix_start.saturating_add(suffix_length),
            );
        }
    }
}

fn scan_assignment(bytes: &[u8], prefix: &[u8], findings: &mut Vec<SecretFinding>) {
    for start in literal_offsets_ascii_case_insensitive(bytes, prefix) {
        let value_start = start.saturating_add(prefix.len());
        let value_length = bytes
            .get(value_start..)
            .map(|suffix| {
                suffix
                    .iter()
                    .take_while(|byte| !byte.is_ascii_whitespace() && !matches!(byte, b'\'' | b'"'))
                    .count()
            })
            .unwrap_or_default();
        if value_length >= 8 {
            push_finding(
                findings,
                SecretKind::CredentialAssignment,
                start,
                value_start.saturating_add(value_length),
            );
        }
    }
}

fn scan_entropy_tokens(bytes: &[u8], findings: &mut Vec<SecretFinding>) {
    for (start, token) in token_runs(bytes) {
        if high_entropy_candidate(token) {
            push_finding(
                findings,
                SecretKind::HighEntropy,
                start,
                start.saturating_add(token.len()),
            );
        }
    }
}

fn scan_encoded_tokens(bytes: &[u8], findings: &mut Vec<SecretFinding>) {
    for (start, token) in token_runs(bytes) {
        if token.len() < 32 || token.len() > 4_096 {
            continue;
        }
        let decoded = STANDARD
            .decode(token)
            .or_else(|_error| URL_SAFE_NO_PAD.decode(token));
        if decoded
            .as_deref()
            .is_ok_and(|value| value.len() >= 24 && high_entropy_candidate(value))
        {
            push_finding(
                findings,
                SecretKind::EncodedSecret,
                start,
                start.saturating_add(token.len()),
            );
        }
    }
}

fn token_runs(bytes: &[u8]) -> Vec<(usize, &[u8])> {
    let mut runs = Vec::new();
    let mut start = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if is_entropy_token_byte(byte) {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take()
            && let Some(token) = bytes.get(begin..index)
        {
            runs.push((begin, token));
        }
    }
    if let Some(begin) = start
        && let Some(token) = bytes.get(begin..)
    {
        runs.push((begin, token));
    }
    runs
}

fn high_entropy_candidate(token: &[u8]) -> bool {
    if token.len() < 32 || token.len() > 4_096 {
        return false;
    }
    let mut seen = [false; 256];
    let mut unique = 0_usize;
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    for byte in token {
        let index = usize::from(*byte);
        if let Some(slot) = seen.get_mut(index)
            && !*slot
        {
            *slot = true;
            unique += 1;
        }
        match byte {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' => digit = true,
            _other => symbol = true,
        }
    }
    let class_count = [lower, upper, digit, symbol]
        .into_iter()
        .filter(|present| *present)
        .count();
    unique >= 20 && class_count >= 3
}

fn is_entropy_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')
}

fn literal_offsets(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || bytes.len() < needle.len() {
        return Vec::new();
    }
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == needle).then_some(index))
        .collect()
}

fn literal_offsets_ascii_case_insensitive(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || bytes.len() < needle.len() {
        return Vec::new();
    }
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, candidate)| candidate.eq_ignore_ascii_case(needle).then_some(index))
        .collect()
}

fn push_finding(findings: &mut Vec<SecretFinding>, kind: SecretKind, start: usize, end: usize) {
    if findings.len() <= MAX_SECRET_FINDINGS {
        findings.push(SecretFinding { kind, start, end });
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

#[cfg(test)]
mod tests {
    use super::{SecretKind, blinded_secret_fingerprint, scan_secrets, scan_secrets_with_patterns};
    use std::collections::BTreeSet;

    #[test]
    fn secret_corpus_is_quarantined_without_debug_reflection() {
        let canary = "password=correct-horse-battery-staple";
        let scan = scan_secrets(canary.as_bytes());
        assert!(scan.must_quarantine());
        assert_eq!(
            scan.findings().first().map(|finding| finding.kind),
            Some(SecretKind::CredentialAssignment)
        );
        assert!(!format!("{scan:?}").contains("correct-horse"));
    }

    #[test]
    fn ordinary_source_is_not_classified_as_secret() {
        let scan = scan_secrets(b"fn main() { println!(\"hello\"); }");
        assert!(!scan.must_quarantine());
        assert!(scan.findings().is_empty());
    }

    #[test]
    fn representative_secret_corpus_covers_every_detector_class() {
        let corpus = [
            b"-----BE".as_slice(),
            b"GIN PRI",
            b"VATE KEY-----\nAK",
            b"IAABCDEFGHIJKLMNOP\nghp_abcdefghijklmnopqrstuvwxyz123456\n",
            b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n",
            b"api_key=abcdefgh12345678",
        ]
        .concat();
        let scan = scan_secrets(&corpus);
        let kinds: BTreeSet<_> = scan.findings().iter().map(|finding| finding.kind).collect();
        for expected in [
            SecretKind::PrivateKey,
            SecretKind::AwsAccessKey,
            SecretKind::GitHubToken,
            SecretKind::BearerToken,
            SecretKind::CredentialAssignment,
        ] {
            assert!(kinds.contains(&expected));
        }
        assert!(scan.must_quarantine());
        assert!(!format!("{scan:?}").contains("abcdefghijklmnop"));
    }

    #[test]
    fn encoded_entropy_and_organization_rules_detect_without_common_false_positive()
    -> Result<(), Box<dyn std::error::Error>> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let encoded = STANDARD.encode((0_u8..128).collect::<Vec<_>>());
        let scan = scan_secrets(encoded.as_bytes());
        assert!(
            scan.findings()
                .iter()
                .any(|finding| finding.kind == SecretKind::EncodedSecret)
        );
        let ordinary = scan_secrets(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(!ordinary.must_quarantine());
        let custom = scan_secrets_with_patterns(
            b"organization-prefix-value",
            &[b"organization-prefix".to_vec()],
        );
        assert!(
            custom
                .findings()
                .iter()
                .any(|finding| finding.kind == SecretKind::OrganizationPattern)
        );
        let finding = custom.findings().first().ok_or("missing custom finding")?;
        let first = blinded_secret_fingerprint(b"organization-prefix-value", finding, &[1_u8; 32])
            .ok_or("missing blinded fingerprint")?;
        let second = blinded_secret_fingerprint(b"organization-prefix-value", finding, &[2_u8; 32])
            .ok_or("missing blinded fingerprint")?;
        assert_ne!(first, second);
        assert!(!format!("{first:?}").contains("organization"));
        Ok(())
    }
}
