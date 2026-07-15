//! Deterministic extraction of the normative PRD surface.

use crate::digest::sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Exact extraction contract. A change to these rules requires a schema/version review.
pub(crate) const EXTRACTION_VERSION: &str = "cigar.prd-requirement-extraction.v1";

/// One machine-discoverable kind of normative source material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequirementKind {
    Normative,
    ReleaseGate,
    SecurityInvariant,
}

/// One exact source span extracted from `prd.md`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExtractedRequirement {
    pub(crate) kinds: Vec<RequirementKind>,
    pub(crate) start_line: usize,
    pub(crate) end_line: usize,
    pub(crate) section: String,
    pub(crate) text: String,
    pub(crate) text_sha256: String,
    pub(crate) normative_token_count: usize,
}

/// Extract every structured normative source span from the PRD.
///
/// The deliberately narrow syntax is fail-closed and reviewable:
///
/// - uppercase `MUST`/`SHALL` statements outside headings, the TOC, and code fences;
/// - `Gate:` and work-packet `**Exit:**` lines;
/// - beta and final release checklist rows;
/// - rows in the `Critical invariant` table; and
/// - bullets in the hard-gate, required-policy, and stop-ship sections.
pub(crate) fn extract_prd_requirements(bytes: &[u8]) -> Result<Vec<ExtractedRequirement>, String> {
    let source = std::str::from_utf8(bytes).map_err(|_error| "PRD is not UTF-8".to_owned())?;
    if source.contains('\r') {
        return Err("PRD must use LF line endings".to_owned());
    }
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() || lines.len() > 100_000 {
        return Err("PRD has an invalid line count".to_owned());
    }

    let mut headings = Vec::<String>::new();
    let mut fence: Option<&str> = None;
    let mut extracted = Vec::new();
    let mut covered_through = 0_usize;

    for (index, line) in lines.iter().enumerate() {
        let line_number = index.saturating_add(1);
        let trimmed = line.trim();
        if let Some(marker) = fence_marker(trimmed) {
            if fence == Some(marker) {
                fence = None;
            } else if fence.is_none() {
                fence = Some(marker);
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }
        if let Some((level, title)) = markdown_heading(line) {
            headings.truncate(level.saturating_sub(1));
            headings.push(normalize_heading(title));
            continue;
        }
        if line_number <= covered_through {
            continue;
        }

        let section = headings.join(" / ");
        let normative_token_count = normative_token_count(trimmed);
        let normative = normative_token_count > 0
            && !is_toc_link(trimmed)
            && !is_requirement_language_definition(trimmed);
        let beta_checklist = section_ends_with(&section, "1.4A Initial beta release lane")
            && is_checklist_item(trimmed);
        let final_checklist = section_ends_with(&section, "Appendix F. Final stop-ship checklist")
            && is_checklist_item(trimmed);
        let release_gate = trimmed.starts_with("Gate:")
            || trimmed.starts_with("**Exit:**")
            || beta_checklist
            || final_checklist;
        let security_invariant = is_critical_invariant_row(&section, trimmed)
            || is_security_invariant_bullet(&section, trimmed);

        let mut kinds = BTreeSet::new();
        if normative {
            kinds.insert(RequirementKind::Normative);
        }
        if release_gate {
            kinds.insert(RequirementKind::ReleaseGate);
        }
        if security_invariant {
            kinds.insert(RequirementKind::SecurityInvariant);
        }
        if kinds.is_empty() {
            continue;
        }

        let end_index = if normative && trimmed.ends_with(':') {
            normative_list_end(&lines, index)
        } else {
            index
        };
        covered_through = end_index.saturating_add(1);
        let text = normalize_source_span(
            lines
                .get(index..=end_index)
                .ok_or_else(|| "PRD extraction span exceeded source".to_owned())?,
        );
        if text.is_empty() || text.len() > 128 * 1024 {
            return Err(format!(
                "PRD line {line_number} has an invalid extracted span"
            ));
        }
        extracted.push(ExtractedRequirement {
            kinds: kinds.into_iter().collect(),
            start_line: line_number,
            end_line: end_index.saturating_add(1),
            section,
            text_sha256: sha256(text.as_bytes()),
            text,
            normative_token_count,
        });
    }
    if fence.is_some() {
        return Err("PRD contains an unterminated fenced code block".to_owned());
    }
    if extracted.is_empty() || extracted.len() > 4096 {
        return Err("PRD extraction produced an invalid requirement count".to_owned());
    }
    Ok(extracted)
}

/// Digest the ordered extracted surface, including locations and classifications.
pub(crate) fn surface_digest(requirements: &[ExtractedRequirement]) -> String {
    let mut canonical = Vec::new();
    for requirement in requirements {
        for kind in &requirement.kinds {
            canonical.extend_from_slice(kind_name(*kind).as_bytes());
            canonical.push(b',');
        }
        canonical.push(0);
        canonical.extend_from_slice(requirement.start_line.to_string().as_bytes());
        canonical.push(b':');
        canonical.extend_from_slice(requirement.end_line.to_string().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(requirement.section.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(requirement.text_sha256.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(requirement.normative_token_count.to_string().as_bytes());
        canonical.push(b'\n');
    }
    sha256(&canonical)
}

pub(crate) const fn kind_name(kind: RequirementKind) -> &'static str {
    match kind {
        RequirementKind::Normative => "normative",
        RequirementKind::ReleaseGate => "release_gate",
        RequirementKind::SecurityInvariant => "security_invariant",
    }
}

fn fence_marker(value: &str) -> Option<&'static str> {
    if value.starts_with("```") {
        Some("```")
    } else if value.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

fn markdown_heading(value: &str) -> Option<(usize, &str)> {
    let bytes = value.as_bytes();
    let level = bytes.iter().take_while(|byte| **byte == b'#').count();
    if !(1..=6).contains(&level) || bytes.get(level) != Some(&b' ') {
        return None;
    }
    value
        .get(level.saturating_add(1)..)
        .map(|title| (level, title))
}

fn normalize_heading(value: &str) -> String {
    value
        .trim()
        .replace("**", "")
        .replace("\\.", ".")
        .replace("\\-", "-")
}

fn section_ends_with(section: &str, expected: &str) -> bool {
    section == expected || section.ends_with(&format!(" / {expected}"))
}

fn is_toc_link(value: &str) -> bool {
    value.starts_with('[') && value.contains("](#")
}

fn is_requirement_language_definition(value: &str) -> bool {
    value.starts_with("MUST, MUST NOT, SHALL, SHALL NOT,") && value.contains("are normative")
}

fn normative_token_count(value: &str) -> usize {
    value
        .split(|character: char| !character.is_ascii_alphabetic())
        .filter(|token| matches!(*token, "MUST" | "SHALL"))
        .count()
}

fn is_checklist_item(value: &str) -> bool {
    [
        "* [ ] ",
        "* [x] ",
        "* [X] ",
        "* \\[ \\] ",
        "* \\[x\\] ",
        "* \\[X\\] ",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn is_critical_invariant_row(section: &str, value: &str) -> bool {
    if !section_ends_with(section, "6.2 Logical tables") || !value.starts_with('|') {
        return false;
    }
    let cells: Vec<&str> = value.split('|').map(str::trim).collect();
    let nonempty_cells: Vec<_> = cells
        .iter()
        .copied()
        .filter(|cell| !cell.is_empty())
        .collect();
    let separator_row = !nonempty_cells.is_empty()
        && nonempty_cells
            .iter()
            .all(|cell| cell.contains('-') && cell.bytes().all(|byte| matches!(byte, b'-' | b':')));
    cells.len() >= 5
        && !value.contains("Critical invariant")
        && !separator_row
        && cells.get(3).is_some_and(|cell| !cell.is_empty())
}

fn is_security_invariant_bullet(section: &str, value: &str) -> bool {
    if !value.starts_with("* ") {
        return false;
    }
    [
        "8.1 Non-bypassable hard gates",
        "8.7 Required policy properties",
        "24.9 Stop-ship conditions",
        "Appendix F. Final stop-ship checklist",
    ]
    .iter()
    .any(|expected| section_ends_with(section, expected))
}

fn normative_list_end(lines: &[&str], start: usize) -> usize {
    let mut end = start;
    let mut index = start.saturating_add(1);
    while let Some(line) = lines.get(index) {
        let trimmed = line.trim();
        if is_list_item(trimmed) {
            end = index;
            index = index.saturating_add(1);
            continue;
        }
        if trimmed.is_empty()
            && lines
                .get(index.saturating_add(1))
                .is_some_and(|next| is_list_item(next.trim()))
        {
            end = index;
            index = index.saturating_add(1);
            continue;
        }
        break;
    }
    end
}

fn is_list_item(value: &str) -> bool {
    if value.starts_with("* ") || value.starts_with("- ") {
        return true;
    }
    let digits = value
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    digits > 0 && value.as_bytes().get(digits..digits.saturating_add(2)) == Some(b". ")
}

fn normalize_source_span(lines: &[&str]) -> String {
    let mut normalized = lines
        .iter()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    normalized = normalized.trim().to_owned();
    normalized
}

#[cfg(test)]
mod tests {
    use super::{RequirementKind, extract_prd_requirements, surface_digest};

    #[test]
    fn extraction_is_structural_complete_and_deterministic() -> Result<(), String> {
        let prd = br#"# Product

MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL are normative.

[How the system SHALL work](#how-the-system-shall-work)

## How the system SHALL work

The runtime MUST reject ambiguity.

Every adapter SHALL:

* preserve identity;
* fail closed.

Gate: the exact candidate passes.

```text
This example MUST not become a requirement.
```

## 6.2 Logical tables

| Table | Key | Critical invariant |
|:--|:--|:--|
| effect | id | exactly once |

## 8.1 Non-bypassable hard gates

* Authentication precedes lookup.
"#;
        let first = extract_prd_requirements(prd)?;
        let second = extract_prd_requirements(prd)?;
        assert_eq!(first, second);
        assert_eq!(first.len(), 5);
        assert_eq!(
            first
                .first()
                .map(|requirement| requirement.kinds.as_slice()),
            Some([RequirementKind::Normative].as_slice())
        );
        assert_eq!(
            first
                .get(1)
                .map(|requirement| (requirement.start_line, requirement.end_line)),
            Some((11, 14))
        );
        assert_eq!(
            first.get(2).map(|requirement| requirement.kinds.as_slice()),
            Some([RequirementKind::ReleaseGate].as_slice())
        );
        assert_eq!(
            first.get(3).map(|requirement| requirement.kinds.as_slice()),
            Some([RequirementKind::SecurityInvariant].as_slice())
        );
        assert_eq!(
            first.get(4).map(|requirement| requirement.kinds.as_slice()),
            Some([RequirementKind::SecurityInvariant].as_slice())
        );
        assert_eq!(surface_digest(&first), surface_digest(&second));
        Ok(())
    }

    #[test]
    fn extraction_rejects_non_utf8_crlf_and_unterminated_fences() {
        assert!(extract_prd_requirements(&[0xff]).is_err());
        assert!(extract_prd_requirements(b"A rule MUST hold.\r\n").is_err());
        assert!(extract_prd_requirements(b"A rule MUST hold.\n```\n").is_err());
    }
}
