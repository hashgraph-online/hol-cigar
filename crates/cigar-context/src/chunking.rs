//! Exact source partitioning at caller-supplied syntax boundaries. No parser or I/O is implicit.

use crate::{ContextError, Document};

impl Document {
    /// Partition exact source bytes at explicit one-based, absolute line starts.
    ///
    /// The first chunk begins at `self.start_line`; `starts` contains only later starts,
    /// strictly increasing. Every chunk must contain non-whitespace text. Nothing is omitted,
    /// normalized or overlapped; LF and CRLF are preserved. IDs use `original_id:L<start>`.
    /// At most 4096 chunks and 16 MiB of input are accepted. Memory for locating boundaries
    /// is proportional to the number of chunks, not the number of lines.
    ///
    /// A caller-owned parser chooses complete syntax units. This function checks source ranges,
    /// not language syntax, execution safety, source authority or semantic dependencies. Replace
    /// the whole source after edits so obsolete chunks are withdrawn; repair hard edges explicitly.
    pub fn chunks_at_lines(&self, starts: &[usize]) -> Result<Vec<Self>, ContextError> {
        if self.text.len() > 16_777_216 || starts.len() >= 4096 {
            return Err(ContextError::LimitExceeded);
        }
        if self.id.len() > 100
            || !crate::graph::valid_id(&self.id)
            || self.start_line == 0
            || self.source.is_empty()
            || self.source.len() > 2048
            || self.source.chars().any(char::is_control)
            || self.text.trim().is_empty()
            || starts.first().is_some_and(|line| *line <= self.start_line)
            || starts.windows(2).any(|pair| pair.first() >= pair.get(1))
        {
            return Err(ContextError::InvalidInput);
        }
        let mut offsets = Vec::with_capacity(starts.len() + 1);
        offsets.push((self.start_line, 0_usize));
        let mut line = self.start_line;
        let mut offset = 0;
        let mut next = 0;
        for text in self.text.split_inclusive('\n') {
            if starts.get(next) == Some(&line) {
                offsets.push((line, offset));
                next += 1;
            }
            offset += text.len();
            if offset < self.text.len() {
                line = line.checked_add(1).ok_or(ContextError::LimitExceeded)?;
            }
        }
        if next != starts.len() {
            return Err(ContextError::InvalidInput);
        }
        let mut chunks = Vec::with_capacity(offsets.len());
        for (index, (start_line, start)) in offsets.iter().copied().enumerate() {
            let end = offsets
                .get(index + 1)
                .map_or(self.text.len(), |(_, offset)| *offset);
            let text = self.text.get(start..end).ok_or(ContextError::Integrity)?;
            if text.trim().is_empty() {
                return Err(ContextError::InvalidInput);
            }
            chunks.push(Self {
                id: format!("{}:L{start_line}", self.id),
                source: self.source.clone(),
                start_line,
                text: text.to_owned(),
            });
        }
        Ok(chunks)
    }
}
