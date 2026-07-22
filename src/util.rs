//! Small shared helpers with no dependencies.

use crate::normalize::classify_invisible;

/// Render a byte range of `input` as a short, display-safe excerpt.
///
/// Any hidden / control character is rendered as a visible `<U+XXXX>` marker so
/// that a snippet placed into a report, log, or terminal cannot itself carry the
/// covert channel it is describing. The range is clamped to char boundaries and
/// truncated to `max_chars` (measured in source characters) with a trailing `…`.
pub fn safe_excerpt(input: &str, start: usize, end: usize, max_chars: usize) -> String {
    let start = floor_char_boundary(input, start.min(input.len()));
    let end = ceil_char_boundary(input, end.min(input.len())).max(start);
    let slice = &input[start..end];
    let mut out = String::new();
    for (n, c) in slice.chars().enumerate() {
        if n >= max_chars {
            out.push('…');
            break;
        }
        out.push_str(&visible_char(c));
    }
    out
}

/// Turn a single character into a display-safe string: printable characters pass
/// through; hidden/control characters become `<U+XXXX>`.
pub fn visible_char(c: char) -> String {
    if classify_invisible(c).is_some() {
        format!("<U+{:04X}>", c as u32)
    } else {
        c.to_string()
    }
}

/// Render an entire string display-safe (used for decoded payload previews).
pub fn visible_string(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max_chars {
            out.push('…');
            break;
        }
        out.push_str(&visible_char(c));
    }
    out
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_chars_become_visible_markers() {
        let s = "a\u{200B}b";
        let out = safe_excerpt(s, 0, s.len(), 10);
        assert_eq!(out, "a<U+200B>b");
    }

    #[test]
    fn truncates_to_max_chars() {
        let out = safe_excerpt("abcdef", 0, 6, 3);
        assert_eq!(out, "abc…");
    }

    #[test]
    fn clamps_to_char_boundaries() {
        // Multi-byte char; a mid-char offset must not panic.
        let s = "é"; // 2 bytes
        let out = safe_excerpt(s, 0, 1, 10);
        assert_eq!(out, "é");
    }
}
