//! Parsing of the hexadecimal text input format and hex formatting helpers.
//!
//! Input format: every byte is written as one or two hexadecimal digits
//! (upper or lower case), bytes are separated by whitespace (spaces, tabs or
//! line breaks). Everything from a `#` to the end of the line is a comment,
//! which makes it possible to annotate sample files.

use std::fmt;

/// Error describing the first token in the input that is not a valid byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexParseError {
    /// 1-based line number of the offending token.
    pub line: usize,
    /// 1-based column (in characters) of the offending token.
    pub column: usize,
    /// The offending token itself.
    pub token: String,
    /// Number of bytes that were parsed successfully before the error.
    pub byte_offset: usize,
}

impl fmt::Display for HexParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid hex byte '{}' at line {}, column {} (after {} valid bytes)",
            self.token, self.line, self.column, self.byte_offset
        )
    }
}

impl std::error::Error for HexParseError {}

/// Parses whitespace separated hex bytes.
///
/// Parsing stops at the first invalid token. All bytes before that token are
/// returned together with the error, so that the caller can still display the
/// valid part of the packet stream.
pub fn parse_hex_text(text: &str) -> (Vec<u8>, Option<HexParseError>) {
    let mut bytes = Vec::new();

    for (line_index, raw_line) in text.lines().enumerate() {
        // Strip comments.
        let line = match raw_line.find('#') {
            Some(pos) => &raw_line[..pos],
            None => raw_line,
        };

        let mut column = 0usize;
        for token in line.split(char::is_whitespace) {
            let token_column = column;
            column += token.chars().count() + 1;
            if token.is_empty() {
                continue;
            }
            match parse_byte_token(token) {
                Some(byte) => bytes.push(byte),
                None => {
                    let error = HexParseError {
                        line: line_index + 1,
                        column: token_column + 1,
                        token: token.to_string(),
                        byte_offset: bytes.len(),
                    };
                    return (bytes, Some(error));
                }
            }
        }
    }

    (bytes, None)
}

/// Parses a single token consisting of one or two hex digits.
fn parse_byte_token(token: &str) -> Option<u8> {
    if token.is_empty() || token.len() > 2 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(token, 16).ok()
}

/// Formats bytes as lower case hex pairs separated by single spaces,
/// e.g. `[0x08, 0x2f]` becomes `"08 2f"`.
pub fn format_hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Formats a field value as lower case hex with `0x` prefix. The number of
/// digits is derived from the bit width of the field, e.g. an 11 bit APID of
/// 47 becomes `"0x02f"`.
pub fn format_hex_value(value: u32, bit_width: u32) -> String {
    let digits = bit_width.div_ceil(4).max(1) as usize;
    format!("0x{value:0digits$x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bytes_and_comments() {
        let (bytes, error) = parse_hex_text("08 2F\tc0\n# comment 99\n0 a # trailing ff\n");
        assert_eq!(error, None);
        assert_eq!(bytes, vec![0x08, 0x2f, 0xc0, 0x00, 0x0a]);
    }

    #[test]
    fn stops_at_first_invalid_token() {
        let (bytes, error) = parse_hex_text("01 02\n03 xyz 04");
        assert_eq!(bytes, vec![1, 2, 3]);
        let error = error.expect("error expected");
        assert_eq!(error.line, 2);
        assert_eq!(error.column, 4);
        assert_eq!(error.token, "xyz");
        assert_eq!(error.byte_offset, 3);
    }

    #[test]
    fn rejects_too_long_tokens() {
        let (bytes, error) = parse_hex_text("0102");
        assert!(bytes.is_empty());
        assert!(error.is_some());
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_hex_bytes(&[0x08, 0x2f, 0xab]), "08 2f ab");
        assert_eq!(format_hex_bytes(&[]), "");
    }

    #[test]
    fn formats_values() {
        assert_eq!(format_hex_value(47, 11), "0x02f");
        assert_eq!(format_hex_value(0x082f, 13), "0x082f");
        assert_eq!(format_hex_value(65535, 16), "0xffff");
    }
}
