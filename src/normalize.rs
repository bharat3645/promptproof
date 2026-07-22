//! Build a *normalized view* of untrusted text and a map back to the original.
//!
//! Attackers hide trigger phrases by splitting words with zero-width characters
//! (`ig<ZWSP>nore`), swapping letters for confusables (`іgnore`), and varying
//! case/whitespace. Matching on the raw bytes misses all of that. So we compute
//! a normalized character stream — invisibles removed, confusables folded to
//! ASCII, lowercased, runs of whitespace collapsed to one space — and remember,
//! for every normalized character, the byte span it came from in the original
//! input. Detectors match on the normalized stream and report **original**
//! offsets via [`Normalized::orig_span`].

use crate::confusables;

/// Class of a hidden / non-printing character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvisibleKind {
    /// Zero-width and invisible-format characters (ZWSP, ZWJ, word joiner, BOM, ...).
    ZeroWidth,
    /// Bidirectional / directional override and mark characters.
    Bidi,
    /// Unicode Tag characters (U+E0000..U+E007F) — an ASCII smuggling channel.
    Tag,
    /// Variation selectors (can carry a covert channel when misused).
    VariationSelector,
    /// C0/C1 control characters other than tab/newline/carriage-return.
    Control,
}

impl InvisibleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InvisibleKind::ZeroWidth => "zero-width",
            InvisibleKind::Bidi => "bidi",
            InvisibleKind::Tag => "tag",
            InvisibleKind::VariationSelector => "variation-selector",
            InvisibleKind::Control => "control",
        }
    }
}

/// Classify a character as a hidden/non-printing character, if it is one.
///
/// Curated set (not the full Unicode `Cf` category — see `confusables.rs` for the
/// same honesty note). Tab, newline and carriage return are treated as ordinary
/// whitespace, not hidden characters.
pub fn classify_invisible(c: char) -> Option<InvisibleKind> {
    let u = c as u32;
    match u {
        0x200B | 0x200C | 0x200D | 0x2060 | 0x2061 | 0x2062 | 0x2063 | 0x2064 | 0xFEFF | 0x00AD
        | 0x180E => Some(InvisibleKind::ZeroWidth),
        0x200E | 0x200F | 0x061C | 0x202A..=0x202E | 0x2066..=0x2069 => Some(InvisibleKind::Bidi),
        0xE0000..=0xE007F => Some(InvisibleKind::Tag),
        0xFE00..=0xFE0F | 0xE0100..=0xE01EF => Some(InvisibleKind::VariationSelector),
        _ => {
            let is_control = (u < 0x20 && u != 0x09 && u != 0x0A && u != 0x0D)
                || u == 0x7F
                || (0x80..=0x9F).contains(&u);
            if is_control {
                Some(InvisibleKind::Control)
            } else {
                None
            }
        }
    }
}

/// A normalized character stream plus a per-character map to original byte spans.
pub struct Normalized {
    /// Normalized characters (folded, lowercased, whitespace-collapsed).
    pub chars: Vec<char>,
    /// `starts[i]` = original byte offset where normalized char `i` came from.
    pub starts: Vec<usize>,
    /// `ends[i]` = original byte offset (exclusive) where normalized char `i` came from.
    pub ends: Vec<usize>,
}

impl Normalized {
    pub fn build(input: &str) -> Normalized {
        let cap = input.len();
        let mut chars = Vec::with_capacity(cap);
        let mut starts = Vec::with_capacity(cap);
        let mut ends = Vec::with_capacity(cap);
        let mut prev_was_space = false;

        for (off, c) in input.char_indices() {
            let len = c.len_utf8();

            if classify_invisible(c).is_some() {
                // Drop it — this is what joins `ig<ZWSP>nore` into `ignore`.
                // Deliberately does not reset `prev_was_space`.
                continue;
            }

            if c.is_whitespace() {
                if !prev_was_space && !chars.is_empty() {
                    chars.push(' ');
                    starts.push(off);
                    ends.push(off + len);
                    prev_was_space = true;
                }
                continue;
            }

            prev_was_space = false;
            let base = confusables::fold(c).unwrap_or(c);
            for lc in base.to_lowercase() {
                chars.push(lc);
                starts.push(off);
                ends.push(off + len);
            }
        }

        Normalized {
            chars,
            starts,
            ends,
        }
    }

    /// The normalized text as a `String` (for display/debugging/tests).
    #[cfg(test)]
    pub fn as_string(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// Map a normalized character range `[ci_start, ci_end)` back to an original
    /// byte span. Panics only if the caller passes an empty or out-of-range range.
    pub fn orig_span(&self, ci_start: usize, ci_end: usize) -> (usize, usize) {
        debug_assert!(ci_start < ci_end && ci_end <= self.chars.len());
        (self.starts[ci_start], self.ends[ci_end - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_width_is_removed_and_joins_words() {
        let n = Normalized::build("ig\u{200B}nore");
        assert_eq!(n.as_string(), "ignore");
    }

    #[test]
    fn confusables_and_case_fold() {
        let n = Normalized::build("Іgnоre"); // Cyrillic I and o
        assert_eq!(n.as_string(), "ignore");
    }

    #[test]
    fn whitespace_collapses() {
        let n = Normalized::build("ignore   \n\t previous");
        assert_eq!(n.as_string(), "ignore previous");
    }

    #[test]
    fn offset_maps_back_to_original() {
        // "a<ZWSP>b" — normalized "ab"; the 'b' originated at byte offset 4
        // (1 for 'a' + 3 for U+200B).
        let n = Normalized::build("a\u{200B}b");
        assert_eq!(n.as_string(), "ab");
        let (s, e) = n.orig_span(1, 2);
        assert_eq!((s, e), (4, 5));
    }

    #[test]
    fn tag_characters_classified() {
        assert_eq!(classify_invisible('\u{E0041}'), Some(InvisibleKind::Tag));
        assert_eq!(classify_invisible('\u{202E}'), Some(InvisibleKind::Bidi));
        assert_eq!(
            classify_invisible('\u{200D}'),
            Some(InvisibleKind::ZeroWidth)
        );
        assert_eq!(classify_invisible('A'), None);
        assert_eq!(classify_invisible('\n'), None);
    }
}
