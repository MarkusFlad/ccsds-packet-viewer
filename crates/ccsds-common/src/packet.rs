//! CCSDS Space Packet data model and stream parser.

use serde::{Deserialize, Serialize};

use crate::hex::{format_hex_value, parse_hex_text, HexParseError};

/// Length of the Packet Primary Header in bytes.
pub const PRIMARY_HEADER_LEN: usize = 6;

/// The only Packet Version Number defined by CCSDS 133.0-B (binary `000`).
pub const SUPPORTED_VERSION: u8 = 0;

/// Value of the "Packet Type" bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketType {
    /// Telemetry (packet type bit = 0).
    TM,
    /// Telecommand (packet type bit = 1).
    TC,
}

impl PacketType {
    /// Creates the packet type from the raw bit value.
    pub fn from_bit(bit: u8) -> Self {
        if bit == 0 {
            PacketType::TM
        } else {
            PacketType::TC
        }
    }

    /// Raw bit value as transmitted in the header.
    pub fn bit(self) -> u8 {
        match self {
            PacketType::TM => 0,
            PacketType::TC => 1,
        }
    }

    /// Short label used in titles ("TM" or "TC").
    pub fn label(self) -> &'static str {
        match self {
            PacketType::TM => "TM",
            PacketType::TC => "TC",
        }
    }
}

/// Decoded fields of the 6 byte Packet Primary Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryHeader {
    /// Packet Version Number (3 bits).
    pub version: u8,
    /// Packet Type (1 bit).
    pub packet_type: PacketType,
    /// Secondary Header Flag (1 bit).
    pub secondary_header_flag: u8,
    /// Application Process Identifier (11 bits).
    pub apid: u16,
    /// Sequence Flags (2 bits).
    pub sequence_flags: u8,
    /// Packet Sequence Count or Packet Name (14 bits).
    pub sequence_count: u16,
    /// Packet Data Length (16 bits): number of octets in the Packet Data Field minus one.
    pub data_length: u16,
}

impl PrimaryHeader {
    /// Bit widths of the individual fields, used for hex formatting.
    pub const VERSION_BITS: u32 = 3;
    pub const PACKET_TYPE_BITS: u32 = 1;
    pub const SECONDARY_HEADER_FLAG_BITS: u32 = 1;
    pub const APID_BITS: u32 = 11;
    pub const SEQUENCE_FLAGS_BITS: u32 = 2;
    pub const SEQUENCE_COUNT_BITS: u32 = 14;
    pub const DATA_LENGTH_BITS: u32 = 16;
    pub const PACKET_IDENTIFICATION_BITS: u32 = 13;
    pub const PACKET_SEQUENCE_CONTROL_BITS: u32 = 16;

    /// Decodes the header from its 6 raw bytes.
    pub fn decode(bytes: &[u8; PRIMARY_HEADER_LEN]) -> Self {
        let word0 = u16::from_be_bytes([bytes[0], bytes[1]]);
        let word1 = u16::from_be_bytes([bytes[2], bytes[3]]);
        let word2 = u16::from_be_bytes([bytes[4], bytes[5]]);

        PrimaryHeader {
            version: ((word0 >> 13) & 0x07) as u8,
            packet_type: PacketType::from_bit(((word0 >> 12) & 0x01) as u8),
            secondary_header_flag: ((word0 >> 11) & 0x01) as u8,
            apid: word0 & 0x07ff,
            sequence_flags: ((word1 >> 14) & 0x03) as u8,
            sequence_count: word1 & 0x3fff,
            data_length: word2,
        }
    }

    /// The 13 bit "Packet Identification" field
    /// (Packet Type, Secondary Header Flag and APID).
    pub fn packet_identification(&self) -> u16 {
        (u16::from(self.packet_type.bit()) << 12)
            | (u16::from(self.secondary_header_flag) << 11)
            | self.apid
    }

    /// The 16 bit "Packet Sequence Control" field
    /// (Sequence Flags and Packet Sequence Count or Packet Name).
    pub fn packet_sequence_control(&self) -> u16 {
        (u16::from(self.sequence_flags) << 14) | self.sequence_count
    }

    /// Number of octets in the Packet Data Field announced by the header.
    pub fn data_field_len(&self) -> usize {
        usize::from(self.data_length) + 1
    }
}

/// A complete, valid Space Packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpacePacket {
    /// Byte offset of the packet within the input stream.
    pub offset: usize,
    /// Raw bytes of the Packet Primary Header.
    pub header_bytes: Vec<u8>,
    /// Decoded Packet Primary Header.
    pub header: PrimaryHeader,
    /// Raw bytes of the Packet Data Field.
    pub data: Vec<u8>,
}

impl SpacePacket {
    /// Title of the packet frame, e.g. `"TM Space Packet APID=47"`.
    pub fn title(&self) -> String {
        format!(
            "{} Space Packet APID={}",
            self.header.packet_type.label(),
            self.header.apid
        )
    }
}

/// Describes the first part of the stream that is not a valid packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidData {
    /// Byte offset at which the invalid data starts.
    pub offset: usize,
    /// Human readable reason why the data is not a valid packet.
    pub reason: String,
    /// Number of bytes from `offset` to the end of the parsed byte stream.
    pub remaining_len: usize,
}

/// Result of parsing a packet stream: all valid packets up to the first
/// invalid one, plus a description of the first invalid packet (if any).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketStream {
    /// Name of the input (usually the file name).
    pub source: String,
    /// All valid packets in stream order.
    pub packets: Vec<SpacePacket>,
    /// The first invalid packet, if the stream does not end cleanly.
    pub invalid: Option<InvalidData>,
}

impl PacketStream {
    /// Parses a stream given as hex text (see [`crate::hex`] for the format).
    pub fn from_hex_text(source: impl Into<String>, text: &str) -> Self {
        let (bytes, hex_error) = parse_hex_text(text);
        let mut stream = parse_packet_stream(source, &bytes);
        if let Some(hex_error) = hex_error {
            stream.attach_hex_error(&hex_error, bytes.len());
        }
        stream
    }

    /// Merges an input text error into the stream result. The text error
    /// truncates the byte stream, so either the packet at the end of the
    /// stream is reported as invalid, or (if the stream ended cleanly) a new
    /// invalid entry is created at the end of the stream.
    fn attach_hex_error(&mut self, error: &HexParseError, stream_len: usize) {
        match &mut self.invalid {
            Some(invalid) => {
                invalid.reason = format!("{}; input text: {}", invalid.reason, error);
            }
            None => {
                self.invalid = Some(InvalidData {
                    offset: stream_len,
                    reason: format!("input text: {error}"),
                    remaining_len: 0,
                });
            }
        }
    }
}

/// Splits a raw byte stream into consecutive Space Packets.
///
/// Parsing stops at the first packet that is not valid. A packet is valid if
/// - at least the 6 bytes of the Packet Primary Header are available,
/// - the Packet Version Number is `0` (binary `000`), and
/// - the complete Packet Data Field announced by the Packet Data Length is
///   available.
pub fn parse_packet_stream(source: impl Into<String>, bytes: &[u8]) -> PacketStream {
    let mut packets = Vec::new();
    let mut invalid = None;
    let mut offset = 0usize;

    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        let invalid_here = |reason: String| InvalidData {
            offset,
            reason,
            remaining_len: remaining.len(),
        };

        let Some(header_bytes) = remaining.first_chunk::<PRIMARY_HEADER_LEN>() else {
            invalid = Some(invalid_here(format!(
                "only {} byte(s) left, a Packet Primary Header needs {}",
                remaining.len(),
                PRIMARY_HEADER_LEN
            )));
            break;
        };

        let header = PrimaryHeader::decode(header_bytes);
        if header.version != SUPPORTED_VERSION {
            invalid = Some(invalid_here(format!(
                "unsupported Packet Version Number {} (expected {})",
                header.version, SUPPORTED_VERSION
            )));
            break;
        }

        let total_len = PRIMARY_HEADER_LEN + header.data_field_len();
        if remaining.len() < total_len {
            invalid = Some(invalid_here(format!(
                "Packet Data Length announces {} data byte(s), only {} available",
                header.data_field_len(),
                remaining.len() - PRIMARY_HEADER_LEN
            )));
            break;
        }

        packets.push(SpacePacket {
            offset,
            header_bytes: header_bytes.to_vec(),
            header,
            data: remaining[PRIMARY_HEADER_LEN..total_len].to_vec(),
        });
        offset += total_len;
    }

    PacketStream {
        source: source.into(),
        packets,
        invalid,
    }
}

/// Formatted representation of a numeric field value for the detail view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldValue {
    /// Decimal representation.
    pub decimal: String,
    /// Hex representation with `0x` prefix, only present if the field can
    /// hold values greater than 9.
    pub hex: Option<String>,
}

impl FieldValue {
    /// Formats a value of a field with the given bit width.
    pub fn new(value: u32, bit_width: u32) -> Self {
        let max_value = (1u64 << bit_width) - 1;
        FieldValue {
            decimal: value.to_string(),
            hex: (max_value > 9).then(|| format_hex_value(value, bit_width)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TM packet, APID 47, unsegmented, sequence count 1, 4 data bytes.
    const TM_PACKET: [u8; 10] = [0x08, 0x2f, 0xc0, 0x01, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef];

    #[test]
    fn decodes_primary_header() {
        let header = PrimaryHeader::decode(TM_PACKET[..6].try_into().unwrap());
        assert_eq!(header.version, 0);
        assert_eq!(header.packet_type, PacketType::TM);
        assert_eq!(header.secondary_header_flag, 1);
        assert_eq!(header.apid, 47);
        assert_eq!(header.sequence_flags, 3);
        assert_eq!(header.sequence_count, 1);
        assert_eq!(header.data_length, 3);
        assert_eq!(header.packet_identification(), 0x082f);
        assert_eq!(header.packet_sequence_control(), 0xc001);
    }

    #[test]
    fn decodes_tc_type() {
        let header = PrimaryHeader::decode(&[0x18, 0x64, 0xc0, 0x00, 0x00, 0x00]);
        assert_eq!(header.packet_type, PacketType::TC);
        assert_eq!(header.apid, 100);
        assert_eq!(header.packet_identification(), 0x1864);
    }

    #[test]
    fn parses_consecutive_packets() {
        let mut bytes = TM_PACKET.to_vec();
        bytes.extend_from_slice(&[0x18, 0x64, 0xc0, 0x00, 0x00, 0x00, 0x42]);
        let stream = parse_packet_stream("test", &bytes);
        assert_eq!(stream.packets.len(), 2);
        assert_eq!(stream.invalid, None);
        assert_eq!(stream.packets[0].title(), "TM Space Packet APID=47");
        assert_eq!(stream.packets[1].title(), "TC Space Packet APID=100");
        assert_eq!(stream.packets[1].offset, 10);
        assert_eq!(stream.packets[1].data, vec![0x42]);
    }

    #[test]
    fn reports_truncated_packet() {
        let mut bytes = TM_PACKET.to_vec();
        bytes.extend_from_slice(&TM_PACKET[..8]);
        let stream = parse_packet_stream("test", &bytes);
        assert_eq!(stream.packets.len(), 1);
        let invalid = stream.invalid.expect("invalid packet expected");
        assert_eq!(invalid.offset, 10);
        assert_eq!(invalid.remaining_len, 8);
    }

    #[test]
    fn reports_short_header() {
        let stream = parse_packet_stream("test", &[0x08, 0x2f]);
        assert!(stream.packets.is_empty());
        assert_eq!(stream.invalid.unwrap().offset, 0);
    }

    #[test]
    fn reports_wrong_version() {
        let stream = parse_packet_stream("test", &[0x28, 0x2f, 0xc0, 0x01, 0x00, 0x00, 0x00]);
        assert!(stream.packets.is_empty());
        assert!(stream.invalid.unwrap().reason.contains("Version"));
    }

    #[test]
    fn hex_text_error_marks_stream_end() {
        let stream = PacketStream::from_hex_text("t", "08 2f c0 01 00 03 de ad be ef zz");
        assert_eq!(stream.packets.len(), 1);
        let invalid = stream.invalid.unwrap();
        assert_eq!(invalid.offset, 10);
        assert!(invalid.reason.contains("zz"));
    }

    #[test]
    fn field_value_formatting() {
        assert_eq!(FieldValue::new(5, 3).hex, None);
        assert_eq!(FieldValue::new(47, 11).hex.as_deref(), Some("0x02f"));
        assert_eq!(FieldValue::new(47, 11).decimal, "47");
        assert_eq!(FieldValue::new(3, 2).hex, None);
    }
}
