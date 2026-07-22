//! Curated confusable folding: map a Unicode "look-alike" character to the ASCII
//! letter/digit it imitates, so obfuscated trigger words (`іgnore`, `ｉｇｎｏｒｅ`,
//! `𝐢𝐠𝐧𝐨𝐫𝐞`) collapse to their plain form before pattern matching.
//!
//! This is deliberately **curated, not the full Unicode confusables database**
//! (that is a large data table and would pull in a dependency or a generated
//! blob). It covers the high-value evasion channels seen against LLMs:
//!   * fullwidth Latin/digits (U+FF01 block),
//!   * the fully-contiguous Mathematical Alphanumeric blocks (bold, italic,
//!     bold-italic, sans-serif and its variants, monospace) plus math digits,
//!   * a hand-picked set of Cyrillic and Greek letters that are near-perfect
//!     Latin look-alikes.
//!
//! The holey math blocks (script / fraktur / double-struck letters, whose
//! members are scattered into the Letterlike Symbols block) are intentionally
//! not folded, to avoid mis-mapping. This is a hardening layer, not a proof.

/// Fold a single character to the ASCII character it visually imitates.
/// Returns `None` when the character is not a recognised confusable (including
/// plain ASCII, which the caller lowercases separately).
pub fn fold(c: char) -> Option<char> {
    if c.is_ascii() {
        return None;
    }
    if let Some(a) = fold_fullwidth(c) {
        return Some(a);
    }
    if let Some(a) = fold_math_alnum(c) {
        return Some(a);
    }
    fold_cyrillic_greek(c)
}

fn fold_fullwidth(c: char) -> Option<char> {
    let u = c as u32;
    match u {
        0xFF21..=0xFF3A => Some((b'A' + (u - 0xFF21) as u8) as char), // Ａ-Ｚ
        0xFF41..=0xFF5A => Some((b'a' + (u - 0xFF41) as u8) as char), // ａ-ｚ
        0xFF10..=0xFF19 => Some((b'0' + (u - 0xFF10) as u8) as char), // ０-９
        _ => None,
    }
}

/// Fold the contiguous (hole-free) Mathematical Alphanumeric letter blocks and
/// the math digit blocks. Each letter block is 52 code points: A-Z then a-z.
fn fold_math_alnum(c: char) -> Option<char> {
    let u = c as u32;

    // (block_base, is_letters) for the 8 fully-contiguous A-Z,a-z blocks.
    const LETTER_BASES: [u32; 8] = [
        0x1D400, // bold
        0x1D434, // italic
        0x1D468, // bold italic
        0x1D5A0, // sans-serif
        0x1D5D4, // sans-serif bold
        0x1D608, // sans-serif italic
        0x1D63C, // sans-serif bold italic
        0x1D670, // monospace
    ];
    for base in LETTER_BASES {
        if u >= base && u < base + 26 {
            return Some((b'A' + (u - base) as u8) as char);
        }
        if u >= base + 26 && u < base + 52 {
            return Some((b'a' + (u - base - 26) as u8) as char);
        }
    }

    // Math digit blocks (each 10 code points, 0-9).
    const DIGIT_BASES: [u32; 5] = [
        0x1D7CE, // bold
        0x1D7D8, // double-struck
        0x1D7E2, // sans-serif
        0x1D7EC, // sans-serif bold
        0x1D7F6, // monospace
    ];
    for base in DIGIT_BASES {
        if u >= base && u < base + 10 {
            return Some((b'0' + (u - base) as u8) as char);
        }
    }
    None
}

/// Hand-picked Cyrillic and Greek letters that are near-identical to a Latin
/// letter. Only near-perfect look-alikes are included; ambiguous ones are left
/// out so folding never invents a match that a human eye would not also read.
fn fold_cyrillic_greek(c: char) -> Option<char> {
    let out = match c {
        // Cyrillic lowercase
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'і' => 'i',
        'ѕ' => 's',
        'ј' => 'j',
        'ԁ' => 'd',
        'һ' => 'h',
        'к' => 'k',
        'м' => 'm',
        'т' => 't',
        'ѵ' => 'v',
        // Cyrillic uppercase
        'А' => 'A',
        'В' => 'B',
        'Е' => 'E',
        'К' => 'K',
        'М' => 'M',
        'Н' => 'H',
        'О' => 'O',
        'Р' => 'P',
        'С' => 'C',
        'Т' => 'T',
        'Х' => 'X',
        'У' => 'Y',
        'І' => 'I',
        'Ѕ' => 'S',
        'Ј' => 'J',
        // Greek lowercase
        'α' => 'a',
        'ο' => 'o',
        'ρ' => 'p',
        'ι' => 'i',
        'ν' => 'v',
        'τ' => 't',
        'γ' => 'y',
        'κ' => 'k',
        'ε' => 'e',
        // Greek uppercase
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Υ' => 'Y',
        'Χ' => 'X',
        _ => return None,
    };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_not_folded() {
        for c in "abcXYZ0189".chars() {
            assert_eq!(fold(c), None);
        }
    }

    #[test]
    fn fullwidth_folds() {
        assert_eq!(fold('ｉ'), Some('i'));
        assert_eq!(fold('Ｇ'), Some('G'));
        assert_eq!(fold('７'), Some('7'));
    }

    #[test]
    fn math_bold_and_monospace_fold() {
        assert_eq!(fold('𝐢'), Some('i')); // math bold i
        assert_eq!(fold('𝐀'), Some('A')); // math bold A
        assert_eq!(fold('𝚉'), Some('Z')); // monospace Z
        assert_eq!(fold('𝟏'), Some('1')); // math bold 1
    }

    #[test]
    fn cyrillic_greek_fold() {
        assert_eq!(fold('і'), Some('i')); // Cyrillic i
        assert_eq!(fold('а'), Some('a')); // Cyrillic a
        assert_eq!(fold('ο'), Some('o')); // Greek omicron
    }

    #[test]
    fn folding_reconstructs_a_hidden_word() {
        let word = "іgnоrе"; // Cyrillic i, o, e mixed into "ignore"
        let folded: String = word.chars().map(|c| fold(c).unwrap_or(c)).collect();
        assert_eq!(folded, "ignore");
    }
}
