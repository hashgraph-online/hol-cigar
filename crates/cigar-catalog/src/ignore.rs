use crate::{CatalogError, CatalogErrorCode, ConnectorContext};

pub(crate) const MAX_IGNORE_BYTES: u64 = 1_048_576;
const MAX_IGNORE_PATTERNS: usize = 4_096;
const MAX_IGNORE_PATTERN_BYTES: usize = 4_096;
const MAX_IGNORE_NORMALIZED_BYTES: usize = 1_048_576;
const MAX_IGNORE_MATCH_STEPS: u64 = 67_108_864;

#[derive(Clone, Default)]
pub(crate) struct IgnorePatterns {
    patterns: Vec<Vec<u8>>,
    source_bytes: usize,
}

impl IgnorePatterns {
    pub(crate) fn parse(bytes: &[u8], context: &ConnectorContext) -> Result<Self, CatalogError> {
        if u64::try_from(bytes.len())
            .ok()
            .is_none_or(|len| len > MAX_IGNORE_BYTES)
        {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        let mut patterns = Vec::new();
        let mut normalized_bytes = 0_usize;
        for raw_line in bytes.split(|byte| *byte == b'\n') {
            context.check()?;
            let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            let line = trim_ascii(raw_line);
            if line.is_empty() {
                continue;
            }
            if raw_line != line {
                return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
            }
            if line.starts_with(b"#") || line.starts_with(b"!") {
                continue;
            }
            let line = line.strip_prefix(b"/").unwrap_or(line);
            if line.is_empty()
                || line.contains(&b'\\')
                || line.contains(&b'?')
                || line.contains(&b'[')
                || line.contains(&b']')
            {
                return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
            }
            if line.len() > MAX_IGNORE_PATTERN_BYTES || patterns.len() == MAX_IGNORE_PATTERNS {
                return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
            }
            normalized_bytes = normalized_bytes
                .checked_add(line.len())
                .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
            if normalized_bytes > MAX_IGNORE_NORMALIZED_BYTES {
                return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
            }
            patterns.push(line.to_vec());
        }
        Ok(Self {
            patterns,
            source_bytes: bytes.len(),
        })
    }

    pub(crate) const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub(crate) fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    pub(crate) fn matches_filesystem(
        &self,
        path: &[u8],
        work: &mut IgnoreWorkBudget,
        context: &ConnectorContext,
    ) -> Result<bool, CatalogError> {
        for pattern in &self.patterns {
            work.charge(1, context)?;
            if positive_pattern_match(pattern, path, work, context)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn matches_git(
        &self,
        path: &[u8],
        work: &mut IgnoreWorkBudget,
        context: &ConnectorContext,
    ) -> Result<bool, CatalogError> {
        self.matches_filesystem(path, work, context)
    }
}

fn positive_pattern_match(
    pattern: &[u8],
    path: &[u8],
    work: &mut IgnoreWorkBudget,
    context: &ConnectorContext,
) -> Result<bool, CatalogError> {
    if wildcard_match(pattern, path, work, context)? {
        return Ok(true);
    }
    let basename_pattern = pattern.strip_suffix(b"/").unwrap_or(pattern);
    if !basename_pattern.contains(&b'/') {
        for component in path.split(|byte| *byte == b'/') {
            if wildcard_match(basename_pattern, component, work, context)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Default)]
pub(crate) struct IgnoreWorkBudget {
    steps: u64,
}

impl IgnoreWorkBudget {
    fn charge(&mut self, steps: u64, context: &ConnectorContext) -> Result<(), CatalogError> {
        context.check()?;
        self.steps = self
            .steps
            .checked_add(steps)
            .ok_or_else(|| CatalogError::new(CatalogErrorCode::LimitExceeded))?;
        if self.steps > MAX_IGNORE_MATCH_STEPS {
            return Err(CatalogError::new(CatalogErrorCode::LimitExceeded));
        }
        Ok(())
    }
}

fn wildcard_match(
    pattern: &[u8],
    value: &[u8],
    work: &mut IgnoreWorkBudget,
    context: &ConnectorContext,
) -> Result<bool, CatalogError> {
    let mut pattern_index = 0_usize;
    let mut value_index = 0_usize;
    let mut star = None;
    let mut retry = 0_usize;
    while value_index < value.len() {
        work.charge(1, context)?;
        if pattern.get(pattern_index) == value.get(value_index) {
            pattern_index += 1;
            value_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry = value_index;
        } else if let Some(star_index) = star {
            retry += 1;
            value_index = retry;
            pattern_index = star_index + 1;
        } else {
            return Ok(pattern.last() == Some(&b'/') && path_has_prefix(value, pattern));
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        work.charge(1, context)?;
        pattern_index += 1;
    }
    Ok(pattern_index == pattern.len()
        || (pattern.last() == Some(&b'/') && path_has_prefix(value, pattern)))
}

pub(crate) fn path_has_prefix(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| prefix.ends_with(b"/") || suffix.first() == Some(&b'/'))
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = bytes.get(1..).unwrap_or_default();
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = bytes
            .get(..bytes.len().saturating_sub(1))
            .unwrap_or_default();
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        IgnorePatterns, IgnoreWorkBudget, MAX_IGNORE_BYTES, MAX_IGNORE_MATCH_STEPS,
        MAX_IGNORE_PATTERN_BYTES,
    };
    use crate::{CatalogErrorCode, ConnectorContext};
    use cigar_store::CancellationToken;
    use std::time::{Duration, Instant};

    fn context() -> ConnectorContext {
        ConnectorContext::new(
            CancellationToken::default(),
            Instant::now() + Duration::from_secs(10),
        )
    }

    #[test]
    fn rejects_oversized_raw_and_normalized_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let maximum = usize::try_from(MAX_IGNORE_BYTES)?;
        let oversized = vec![b'a'; maximum + 1];
        let error = IgnorePatterns::parse(&oversized, &context())
            .err()
            .ok_or("oversized ignore input must fail")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);

        let mut patterns = Vec::new();
        for _index in 0..=4_096 {
            patterns.extend_from_slice(b"a\n");
        }
        let error = IgnorePatterns::parse(&patterns, &context())
            .err()
            .ok_or("too many patterns must fail")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);

        let oversized_pattern = vec![b'a'; MAX_IGNORE_PATTERN_BYTES + 1];
        let error = IgnorePatterns::parse(&oversized_pattern, &context())
            .err()
            .ok_or("an oversized normalized pattern must fail")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn wildcard_matching_remains_bounded_and_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let patterns = IgnorePatterns::parse(b"target/*\n*.pem\n", &context())?;
        let mut work = IgnoreWorkBudget::default();
        assert!(patterns.matches_filesystem(b"target/a.rs", &mut work, &context())?);
        assert!(patterns.matches_filesystem(b"private.pem", &mut work, &context())?);
        assert!(patterns.matches_filesystem(b"nested/private.pem", &mut work, &context())?);
        assert!(!patterns.matches_filesystem(b"src/lib.rs", &mut work, &context())?);

        let mut exhausted = IgnoreWorkBudget {
            steps: MAX_IGNORE_MATCH_STEPS,
        };
        let error = patterns
            .matches_filesystem(b"src/lib.rs", &mut exhausted, &context())
            .err()
            .ok_or("matching must reject the first work step over budget")?;
        assert_eq!(error.code(), CatalogErrorCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn unsupported_git_syntax_fails_instead_of_silently_under_ignoring() {
        for pattern in [b"file?.txt".as_slice(), b"[ab].txt", b"escaped\\ name"] {
            assert_eq!(
                IgnorePatterns::parse(pattern, &context())
                    .err()
                    .map(|error| error.code()),
                Some(CatalogErrorCode::InvalidMetadata)
            );
        }
    }
}
