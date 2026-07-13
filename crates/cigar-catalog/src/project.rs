//! Stable tenant-scoped project identity independent of a current filesystem location.

use crate::{CatalogError, CatalogErrorCode};
use cigar_protocol::RecordId;
use sha2::{Digest, Sha256};
use std::fmt;

/// Explicit persisted inputs used to distinguish moves, worktrees, and forks.
#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentityInput {
    /// Owning tenant namespace.
    pub tenant_id: RecordId,
    /// Git remote identity when one is available; credentials are rejected and removed.
    pub git_remote: Option<String>,
    /// Persisted repository-root lineage generated at first attachment.
    pub root_lineage_id: RecordId,
    /// Explicit bounded fork/worktree disambiguator.
    pub disambiguator: String,
}

impl fmt::Debug for ProjectIdentityInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentityInput")
            .field("has_remote", &self.git_remote.is_some())
            .field("disambiguator_bytes", &self.disambiguator.len())
            .finish_non_exhaustive()
    }
}

/// Stable project identity and its normalized credential-free remote fingerprint input.
#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    /// Tenant-scoped deterministic project UUIDv7-shaped identity.
    pub project_id: RecordId,
    /// Credential-free normalized remote, absent for local-only projects.
    normalized_remote: Option<String>,
}

impl ProjectIdentity {
    /// Derives an identity that is unchanged by directory moves and explicit worktree relocation.
    pub fn derive(input: ProjectIdentityInput) -> Result<Self, CatalogError> {
        if input.disambiguator.is_empty()
            || input.disambiguator.len() > 256
            || input
                .disambiguator
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        let normalized_remote = input
            .git_remote
            .as_deref()
            .map(normalize_remote)
            .transpose()?;
        let remote = normalized_remote.as_deref().unwrap_or("local");
        let project_id = RecordId::new(deterministic_uuid(&[
            b"CIGAR-PROJECT-IDENTITY\0v1\0",
            input.tenant_id.as_str().as_bytes(),
            input.root_lineage_id.as_str().as_bytes(),
            remote.as_bytes(),
            input.disambiguator.as_bytes(),
        ]))
        .map_err(|_error| CatalogError::new(CatalogErrorCode::InvalidRecord))?;
        Ok(Self {
            project_id,
            normalized_remote,
        })
    }

    /// Returns the normalized remote only to an authorized catalog caller.
    #[must_use]
    pub fn normalized_remote(&self) -> Option<&str> {
        self.normalized_remote.as_deref()
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("project_id", &self.project_id)
            .field("has_remote", &self.normalized_remote.is_some())
            .finish()
    }
}

fn normalize_remote(remote: &str) -> Result<String, CatalogError> {
    if remote.is_empty()
        || remote.len() > 4_096
        || remote
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
    }
    let normalized = if let Some((scheme, remainder)) = remote.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "https" | "ssh" | "git" | "file") {
            return Err(CatalogError::new(CatalogErrorCode::Denied));
        }
        let (authority, path) = remainder.split_once('/').unwrap_or((remainder, ""));
        let host = authority.rsplit_once('@').map_or(authority, |pair| pair.1);
        if host.is_empty() {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        format!("{scheme}://{}/{path}", host.to_ascii_lowercase())
    } else if let Some((authority, path)) = remote.split_once(':') {
        let host = authority.rsplit_once('@').map_or(authority, |pair| pair.1);
        if host.is_empty() || path.is_empty() {
            return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
        }
        format!("ssh://{}/{path}", host.to_ascii_lowercase())
    } else {
        return Err(CatalogError::new(CatalogErrorCode::InvalidMetadata));
    };
    Ok(normalized
        .trim_end_matches('/')
        .strip_suffix(".git")
        .unwrap_or(normalized.trim_end_matches('/'))
        .to_owned())
}

fn deterministic_uuid(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, ..] = digest;
    let g = (g & 0x0f) | 0x70;
    let i = (i & 0x3f) | 0x80;
    format!(
        "{a:02x}{b:02x}{c:02x}{d:02x}-{e:02x}{f:02x}-{g:02x}{h:02x}-{i:02x}{j:02x}-{k:02x}{l:02x}{m:02x}{n:02x}{o:02x}{p:02x}"
    )
}

#[cfg(test)]
mod tests {
    use super::{ProjectIdentity, ProjectIdentityInput};
    use cigar_protocol::RecordId;

    fn input(disambiguator: &str) -> Result<ProjectIdentityInput, Box<dyn std::error::Error>> {
        Ok(ProjectIdentityInput {
            tenant_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7890")?,
            git_remote: Some("git@example.COM:Org/Repo.git".to_owned()),
            root_lineage_id: RecordId::new("01890f47-8e7d-7b42-a1d2-3c4d5e6f7891")?,
            disambiguator: disambiguator.to_owned(),
        })
    }

    #[test]
    fn remote_credentials_are_removed_moves_are_stable_and_forks_are_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = ProjectIdentity::derive(input("primary")?)?;
        let moved = ProjectIdentity::derive(input("primary")?)?;
        let fork = ProjectIdentity::derive(input("fork")?)?;
        assert_eq!(first.project_id, moved.project_id);
        assert_ne!(first.project_id, fork.project_id);
        assert_eq!(
            first.normalized_remote(),
            Some("ssh://example.com/Org/Repo")
        );
        assert!(!format!("{first:?}").contains("Org/Repo"));
        Ok(())
    }
}
