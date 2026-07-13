//! Small strict JSON codec used at the untrusted stdio boundary.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::iter::Peekable;
use std::str::Chars;

pub(crate) const REQUEST_MAX_DEPTH: usize = 32;
pub(crate) const REQUEST_MAX_NODES: usize = 8_192;
pub(crate) const REQUEST_MAX_STRING_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl Value {
    pub(crate) fn object_field(&self, name: &str) -> Option<&Self> {
        let Self::Object(fields) = self else {
            return None;
        };
        fields
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value))
    }

    pub(crate) fn as_object(&self) -> Option<&[(String, Self)]> {
        let Self::Object(fields) = self else {
            return None;
        };
        Some(fields)
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        let Self::String(value) = self else {
            return None;
        };
        Some(value)
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        let Self::Number(value) = self else {
            return None;
        };
        if value.starts_with('-') || value.contains(['.', 'e', 'E']) {
            return None;
        }
        value.parse().ok()
    }

    pub(crate) fn render(&self) -> String {
        let mut rendered = String::new();
        let _result = self.write_json(&mut rendered);
        rendered
    }

    fn write_json(&self, output: &mut String) -> fmt::Result {
        match self {
            Self::Null => output.push_str("null"),
            Self::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => output.push_str(value),
            Self::String(value) => write_string(output, value)?,
            Self::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write_json(output)?;
                }
                output.push(']');
            }
            Self::Object(fields) => {
                output.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_string(output, key)?;
                    output.push(':');
                    value.write_json(output)?;
                }
                output.push('}');
            }
        }
        Ok(())
    }
}

pub(crate) fn object(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

pub(crate) fn string(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

pub(crate) fn number(value: usize) -> Value {
    Value::Number(value.to_string())
}

pub(crate) fn parse(input: &str) -> Result<Value, ParseError> {
    parse_with_limits(
        input,
        REQUEST_MAX_DEPTH,
        REQUEST_MAX_NODES,
        REQUEST_MAX_STRING_BYTES,
    )
}

pub(crate) fn parse_with_limits(
    input: &str,
    max_depth: usize,
    max_nodes: usize,
    max_string_bytes: usize,
) -> Result<Value, ParseError> {
    let mut parser = Parser {
        chars: input.chars().peekable(),
        nodes: 0,
        max_depth,
        max_nodes,
        max_string_bytes,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.chars.peek().is_some() {
        return Err(ParseError);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParseError;

struct Parser<'a> {
    chars: Peekable<Chars<'a>>,
    nodes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_string_bytes: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.nodes = self.nodes.checked_add(1).ok_or(ParseError)?;
        if self.nodes > self.max_nodes || depth > self.max_depth {
            return Err(ParseError);
        }
        match self.chars.peek().copied() {
            Some('n') => self.literal("null", Value::Null),
            Some('t') => self.literal("true", Value::Bool(true)),
            Some('f') => self.literal("false", Value::Bool(false)),
            Some('"') => self.string().map(Value::String),
            Some('[') => self.array(depth),
            Some('{') => self.object(depth),
            Some('-' | '0'..='9') => self.number().map(Value::Number),
            _ => Err(ParseError),
        }
    }

    fn literal(&mut self, expected: &str, value: Value) -> Result<Value, ParseError> {
        for expected_char in expected.chars() {
            if self.chars.next() != Some(expected_char) {
                return Err(ParseError);
            }
        }
        Ok(value)
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        if self.chars.next() != Some('[') {
            return Err(ParseError);
        }
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume(']') {
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value(depth.saturating_add(1))?);
            self.skip_whitespace();
            if self.consume(']') {
                break;
            }
            if !self.consume(',') {
                return Err(ParseError);
            }
            self.skip_whitespace();
        }
        Ok(Value::Array(values))
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        if self.chars.next() != Some('{') {
            return Err(ParseError);
        }
        self.skip_whitespace();
        let mut fields = Vec::new();
        let mut keys = BTreeSet::new();
        if self.consume('}') {
            return Ok(Value::Object(fields));
        }
        loop {
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(ParseError);
            }
            self.skip_whitespace();
            if !self.consume(':') {
                return Err(ParseError);
            }
            self.skip_whitespace();
            let value = self.value(depth.saturating_add(1))?;
            fields.push((key, value));
            self.skip_whitespace();
            if self.consume('}') {
                break;
            }
            if !self.consume(',') {
                return Err(ParseError);
            }
            self.skip_whitespace();
        }
        Ok(Value::Object(fields))
    }

    fn string(&mut self) -> Result<String, ParseError> {
        if self.chars.next() != Some('"') {
            return Err(ParseError);
        }
        let mut output = String::new();
        loop {
            let next = self.chars.next().ok_or(ParseError)?;
            match next {
                '"' => break,
                '\\' => self.escape(&mut output)?,
                '\u{0000}'..='\u{001f}' => return Err(ParseError),
                value => output.push(value),
            }
            if output.len() > self.max_string_bytes {
                return Err(ParseError);
            }
        }
        Ok(output)
    }

    fn escape(&mut self, output: &mut String) -> Result<(), ParseError> {
        match self.chars.next().ok_or(ParseError)? {
            '"' => output.push('"'),
            '\\' => output.push('\\'),
            '/' => output.push('/'),
            'b' => output.push('\u{0008}'),
            'f' => output.push('\u{000c}'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.chars.next() != Some('\\') || self.chars.next() != Some('u') {
                        return Err(ParseError);
                    }
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(ParseError);
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(ParseError);
                } else {
                    u32::from(first)
                };
                output.push(char::from_u32(scalar).ok_or(ParseError)?);
            }
            _ => return Err(ParseError),
        }
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, ParseError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self.chars.next().and_then(|item| item.to_digit(16));
            value = value
                .checked_mul(16)
                .and_then(|prefix| digit.and_then(|part| prefix.checked_add(part as u16)))
                .ok_or(ParseError)?;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<String, ParseError> {
        let mut output = String::new();
        if self.consume('-') {
            output.push('-');
        }
        match self.chars.peek().copied() {
            Some('0') => {
                output.push('0');
                self.chars.next();
                if matches!(self.chars.peek(), Some('0'..='9')) {
                    return Err(ParseError);
                }
            }
            Some('1'..='9') => self.digits(&mut output),
            _ => return Err(ParseError),
        }
        if self.consume('.') {
            output.push('.');
            if !matches!(self.chars.peek(), Some('0'..='9')) {
                return Err(ParseError);
            }
            self.digits(&mut output);
        }
        if matches!(self.chars.peek(), Some('e' | 'E')) {
            let exponent = self.chars.next().ok_or(ParseError)?;
            output.push(exponent);
            if matches!(self.chars.peek(), Some('+' | '-')) {
                output.push(self.chars.next().ok_or(ParseError)?);
            }
            if !matches!(self.chars.peek(), Some('0'..='9')) {
                return Err(ParseError);
            }
            self.digits(&mut output);
        }
        if output.len() > 128 {
            return Err(ParseError);
        }
        Ok(output)
    }

    fn digits(&mut self, output: &mut String) {
        while let Some(value @ '0'..='9') = self.chars.peek().copied() {
            output.push(value);
            self.chars.next();
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.chars.peek().copied() == Some(expected) {
            self.chars.next();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.chars.peek(), Some(' ' | '\n' | '\r' | '\t')) {
            self.chars.next();
        }
    }
}

fn write_string(output: &mut String, value: &str) -> fmt::Result {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => write!(output, "\\u{:04x}", character as u32)?,
            value => output.push(value),
        }
    }
    output.push('"');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Value, parse};

    #[test]
    fn parser_round_trips_unicode_and_numbers() -> Result<(), String> {
        let source = r#"{"a":[null,true,-12.5e+2,"\uD83D\uDE80"]}"#;
        let parsed = parse(source).map_err(|_| "parse")?;
        let encoded = parsed.render();
        assert_eq!(parse(&encoded).map_err(|_| "reparse")?, parsed);
        assert!(encoded.contains('🚀'));
        Ok(())
    }

    #[test]
    fn parser_rejects_duplicate_keys_and_invalid_scalars() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse(r#"{"a":"\uD800"}"#).is_err());
        assert!(parse("01").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":1} trailing").is_err());
    }

    #[test]
    fn accessors_are_type_checked() -> Result<(), String> {
        let value = parse(r#"{"n":12,"s":"ok"}"#).map_err(|_| "parse")?;
        assert_eq!(value.object_field("n").and_then(Value::as_u64), Some(12));
        assert_eq!(value.object_field("s").and_then(Value::as_str), Some("ok"));
        assert!(value.object_field("missing").is_none());
        Ok(())
    }
}
