use cigar_context::{Document, O200kTokenizer, TokenCounter};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

pub(crate) fn words(value: &str) -> Vec<String> {
    let mut split = String::new();
    let mut lower = false;
    for ch in value.chars() {
        if lower && ch.is_uppercase() {
            split.push(' ');
        }
        split.push(ch);
        lower = ch.is_lowercase();
    }
    split
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| s.len() >= 2)
        .map(str::to_lowercase)
        .collect()
}

pub(crate) fn render(documents: &[&Document]) -> Result<String, Box<dyn Error>> {
    documents
        .iter()
        .map(|doc| {
            Ok(serde_json::to_string(&serde_json::json!({
                "sources": [[doc.id,doc.source,doc.start_line,doc.start_line + doc.text.lines().count().saturating_sub(1)]], "text": doc.text
            }))?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()
        .map(|lines| lines.join("\n"))
}

pub(crate) struct Bm25Index {
    corpus: Vec<BTreeMap<String, usize>>,
    lengths: Vec<usize>,
    average: f64,
    df: BTreeMap<String, usize>,
    identifiers: bool,
}

fn analyzed_words(value: &str, identifiers: bool) -> Vec<String> {
    let mut output = words(value);
    if identifiers {
        for token in value.split(|c: char| !c.is_alphanumeric() && c != '_') {
            let camel = token
                .chars()
                .zip(token.chars().skip(1))
                .any(|(a, b)| a.is_lowercase() && b.is_uppercase());
            if token.len() >= 2 && (token.contains('_') || camel) {
                output.push(token.to_lowercase());
            }
        }
    }
    output
}

impl Bm25Index {
    pub(crate) fn new(documents: &[Document], identifiers: bool) -> Self {
        let mut df = BTreeMap::<String, usize>::new();
        let mut lengths = Vec::new();
        let corpus = documents
            .iter()
            .map(|doc| {
                let mut counts = BTreeMap::new();
                let tokens = analyzed_words(&format!("{} {}", doc.source, doc.text), identifiers);
                lengths.push(tokens.len());
                for word in tokens {
                    *counts.entry(word).or_default() += 1;
                }
                for word in counts.keys() {
                    *df.entry(word.clone()).or_default() += 1;
                }
                counts
            })
            .collect();
        let average = lengths.iter().sum::<usize>() as f64 / documents.len().max(1) as f64;
        Self {
            corpus,
            lengths,
            average,
            df,
            identifiers,
        }
    }
}

pub(crate) fn bm25<'a>(
    index: &Bm25Index,
    documents: &'a [Document],
    query: &str,
    tokenizer: &O200kTokenizer,
    budget: usize,
) -> Result<Vec<&'a Document>, Box<dyn Error>> {
    let terms = analyzed_words(query, index.identifiers)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut ranked = documents
        .iter()
        .zip(&index.corpus)
        .zip(&index.lengths)
        .map(|((doc, words), length)| {
            let score = terms
                .iter()
                .map(|term| {
                    let frequency = words.get(term).copied().unwrap_or_default() as f64;
                    let count = index.df.get(term).copied().unwrap_or_default() as f64;
                    let idf = (1.0 + (documents.len() as f64 - count + 0.5) / (count + 0.5)).ln();
                    idf * frequency * 2.2
                        / (frequency
                            + 1.2 * (0.25 + 0.75 * *length as f64 / index.average.max(1.0)))
                })
                .sum::<f64>();
            (doc, score)
        })
        .filter(|(_, score)| *score > 0.0)
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.id.cmp(&b.0.id)));
    let mut selected = Vec::new();
    for (doc, _) in ranked {
        selected.push(doc);
        if tokenizer.count(&render(&selected)?)? > budget {
            selected.pop();
        }
    }
    Ok(selected)
}
