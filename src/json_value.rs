//! A minimal, dependency-free JSON *parser* for reading policy files (see
//! [`crate::allowlist`]). Deliberately narrow: enough to read a small,
//! hand-written config document (nulls/bools/numbers/strings/arrays/objects,
//! with standard string escapes incl. `\uXXXX` surrogate pairs) — not a
//! general-purpose JSON library, and not the inverse of `json.rs`'s emitter
//! (which serializes [`crate::report::Report`], a different concern).

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// Parse a complete JSON document. Trailing non-whitespace bytes are an error.
pub fn parse(input: &str) -> Result<Value, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing data at byte {}", p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", b as char, self.pos))
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(Value::String),
            Some(b't') => self.parse_lit("true", Value::Bool(true)),
            Some(b'f') => self.parse_lit("false", Value::Bool(false)),
            Some(b'n') => self.parse_lit("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(format!("unexpected byte {:?} at {}", c as char, self.pos)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn parse_lit(&mut self, lit: &str, v: Value) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(v)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let val = self.parse_value()?;
            fields.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
        Ok(Value::Object(fields))
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            let v = self.parse_value()?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
        Ok(Value::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_string()),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b'"') => {
                            out.push('"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            out.push('/');
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            out.push('\u{8}');
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            out.push('\u{c}');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            let cp = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.bytes.get(self.pos) == Some(&b'\\')
                                    && self.bytes.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let low = self.parse_hex4()?;
                                    if (0xDC00..=0xDFFF).contains(&low) {
                                        let c = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                        out.push(
                                            char::from_u32(c).ok_or("invalid surrogate pair")?,
                                        );
                                    } else {
                                        return Err("invalid low surrogate".to_string());
                                    }
                                } else {
                                    return Err("unpaired high surrogate".to_string());
                                }
                            } else {
                                out.push(char::from_u32(cp).ok_or("invalid \\u escape")?);
                            }
                        }
                        _ => return Err(format!("invalid escape at byte {}", self.pos)),
                    }
                }
                Some(_) => {
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| "invalid utf-8 in string".to_string())?;
                    let c = rest.chars().next().expect("non-empty after check above");
                    if (c as u32) < 0x20 {
                        return Err(format!("unescaped control char at byte {}", self.pos));
                    }
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated \\u escape".to_string());
        }
        let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| "invalid \\u escape".to_string())?;
        let v = u32::from_str_radix(s, 16).map_err(|_| "invalid \\u escape".to_string())?;
        self.pos += 4;
        Ok(v)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).expect("ascii digits");
        s.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| format!("invalid number at byte {start}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Value::Null);
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(parse("false").unwrap(), Value::Bool(false));
        assert_eq!(parse("42").unwrap(), Value::Number(42.0));
        assert_eq!(parse("-3.5e2").unwrap(), Value::Number(-350.0));
        assert_eq!(parse("\"hi\"").unwrap(), Value::String("hi".into()));
    }

    #[test]
    fn parses_escapes_incl_unicode_and_surrogate_pair() {
        assert_eq!(
            parse(r#""a\nb\tc""#).unwrap(),
            Value::String("a\nb\tc".into())
        );
        assert_eq!(parse(r#""A""#).unwrap(), Value::String("A".into()));
        // U+1F600 GRINNING FACE via surrogate pair.
        assert_eq!(parse(r#""😀""#).unwrap(), Value::String("\u{1F600}".into()));
    }

    #[test]
    fn parses_nested_array_and_object() {
        let v = parse(r#" [ {"a": 1, "b": [true, null, "x"]} ] "#).unwrap();
        let Value::Array(items) = v else {
            panic!("expected array")
        };
        assert_eq!(items.len(), 1);
        let Value::Object(fields) = &items[0] else {
            panic!("expected object")
        };
        assert_eq!(fields[0], ("a".to_string(), Value::Number(1.0)));
        assert_eq!(
            fields[1].1,
            Value::Array(vec![
                Value::Bool(true),
                Value::Null,
                Value::String("x".into())
            ])
        );
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(parse("42 }").is_err());
    }

    #[test]
    fn rejects_unterminated_string() {
        assert!(parse("\"abc").is_err());
    }

    #[test]
    fn rejects_bare_control_char_in_string() {
        assert!(parse("\"a\tb\"").is_err());
    }

    #[test]
    fn rejects_trailing_comma() {
        assert!(parse("[1,]").is_err());
        assert!(parse(r#"{"a":1,}"#).is_err());
    }

    #[test]
    fn empty_array_and_object() {
        assert_eq!(parse("[]").unwrap(), Value::Array(vec![]));
        assert_eq!(parse("{}").unwrap(), Value::Object(vec![]));
    }
}
