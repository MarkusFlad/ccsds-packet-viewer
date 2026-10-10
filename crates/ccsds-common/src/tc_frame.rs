//! CCSDS TC Transfer Frame data model and stream parser
//! (CCSDS 232.0-B-4 "TC Space Data Link Protocol").
//!
//! ```text
//! +----------------+------------+----------+----------------+----------+------------+
//! | Transfer Frame | Segment    | Security | Transfer Frame | Security | Frame      |
//! | Primary Header | Header     | Header   | Data Field     | Trailer  | Error      |
//! | (5 octets)     | (optional, | (opt.)   |                | (opt.)   | Control    |
//! |                |  1 octet)  |          |                |          | (optional, |
//! |                |            |          |                |          |  2 octets) |
//! +----------------+------------+----------+----------------+----------+------------+
//! ```
//!
//! Primary header bit layout:
//!
//! ```text
//! | Version | Bypass | Control | Reserved | Spacecraft | Virtual | Frame  | Frame    |
//! |         | Flag   | Command | Spare    | ID         | Channel | Length | Sequence |
//! |         |        | Flag    |          |            | ID      |        | Number   |
//! | 2       | 1      | 1       | 2        | 10         | 6       | 10     | 8        |
//! ```
//!
//! Segment header bit layout: Sequence Flags (2 bits), Multiplexer Access
//! Point Identifier (6 bits).
//!
//! The length of a frame is contained in its primary header (Frame Length =
//! total number of octets minus one). The presence of the Segment Header, of
//! the Frame Error Control Field and of the Space Data Link Security Protocol
//! fields are managed parameters and have to be configured
//! ([`TcFrameConfig`]). Frames carrying control commands (Control Command
//! Flag 1) contain neither a Segment Header nor security fields.

use serde::{Deserialize, Serialize};

use crate::crc::crc16_ccitt;
use crate::extract::{extract_tc_packets, PacketExtraction};
use crate::frame::{Fecf, SdlsConfig, FECF_LEN, MIN_SECURITY_HEADER_LEN};
use crate::hex::parse_hex_text;
use crate::packet::{merge_hex_error, InvalidData};

/// Length of the Transfer Frame Primary Header in octets.
pub const TC_PRIMARY_HEADER_LEN: usize = 5;
/// Length of the Segment Header in octets.
pub const SEGMENT_HEADER_LEN: usize = 1;
/// Maximum length of a TC Transfer Frame in octets.
pub const MAX_TC_FRAME_LEN: usize = 1024;

/// Managed parameters needed to decode TC frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcFrameConfig {
    /// Frames carrying data start their data field with a Segment Header.
    pub segment_header: bool,
    /// Every frame ends with a 2 octet Frame Error Control Field.
    pub fecf_present: bool,
    /// If `false`, a FECF mismatch is shown but does not make the frame invalid.
    pub check_crc: bool,
    /// Space Data Link Security Protocol fields in every frame carrying
    /// data, if any.
    pub sdls: Option<SdlsConfig>,
}

impl TcFrameConfig {
    /// Checks the configuration, returning a human readable error.
    pub fn validate(&self) -> Result<(), String> {
        if matches!(&self.sdls, Some(sdls) if sdls.header_length < MIN_SECURITY_HEADER_LEN) {
            return Err(format!(
                "Security Header must be at least {MIN_SECURITY_HEADER_LEN} octets long \
                 (Security Parameter Index)"
            ));
        }
        Ok(())
    }
}

/// Decoded fields of the 5 octet Transfer Frame Primary Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcPrimaryHeader {
    /// Transfer Frame Version Number (2 bits).
    pub version: u8,
    /// Bypass Flag (1 bit): `0` = Type-A (sequence controlled), `1` = Type-B
    /// (expedited).
    pub bypass_flag: u8,
    /// Control Command Flag (1 bit): `0` = Type-D (data), `1` = Type-C
    /// (control commands).
    pub control_command_flag: u8,
    /// Reserved Spare (2 bits).
    pub spare: u8,
    /// Spacecraft Identifier (10 bits).
    pub spacecraft_id: u16,
    /// Virtual Channel Identifier (6 bits).
    pub virtual_channel_id: u8,
    /// Frame Length (10 bits): total number of octets minus one.
    pub frame_length: u16,
    /// Frame Sequence Number (8 bits).
    pub frame_sequence_number: u8,
}

impl TcPrimaryHeader {
    pub const VERSION_BITS: u32 = 2;
    pub const BYPASS_FLAG_BITS: u32 = 1;
    pub const CONTROL_COMMAND_FLAG_BITS: u32 = 1;
    pub const SPARE_BITS: u32 = 2;
    pub const SPACECRAFT_ID_BITS: u32 = 10;
    pub const VIRTUAL_CHANNEL_ID_BITS: u32 = 6;
    pub const FRAME_LENGTH_BITS: u32 = 10;
    pub const FRAME_SEQUENCE_NUMBER_BITS: u32 = 8;

    /// Decodes the header from its 5 raw octets.
    pub fn decode(bytes: &[u8; TC_PRIMARY_HEADER_LEN]) -> Self {
        let word0 = u16::from_be_bytes([bytes[0], bytes[1]]);
        let word1 = u16::from_be_bytes([bytes[2], bytes[3]]);

        TcPrimaryHeader {
            version: ((word0 >> 14) & 0x03) as u8,
            bypass_flag: ((word0 >> 13) & 0x01) as u8,
            control_command_flag: ((word0 >> 12) & 0x01) as u8,
            spare: ((word0 >> 10) & 0x03) as u8,
            spacecraft_id: word0 & 0x03ff,
            virtual_channel_id: ((word1 >> 10) & 0x3f) as u8,
            frame_length: word1 & 0x03ff,
            frame_sequence_number: bytes[4],
        }
    }

    /// Total length of the frame in octets.
    pub fn total_length(&self) -> usize {
        usize::from(self.frame_length) + 1
    }

    /// `true` if the frame carries control commands (Type-C).
    pub fn is_control(&self) -> bool {
        self.control_command_flag == 1
    }

    /// Frame type given by Bypass Flag and Control Command Flag.
    pub fn frame_type(&self) -> &'static str {
        match (self.bypass_flag, self.control_command_flag) {
            (0, 0) => "AD",
            (1, 0) => "BD",
            (1, _) => "BC",
            _ => "reserved",
        }
    }
}

/// The optional Segment Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcSegmentHeader {
    /// Sequence Flags (2 bits).
    pub sequence_flags: u8,
    /// Multiplexer Access Point Identifier (6 bits).
    pub map_id: u8,
}

impl TcSegmentHeader {
    pub const SEQUENCE_FLAGS_BITS: u32 = 2;
    pub const MAP_ID_BITS: u32 = 6;

    /// Sequence Flags: first portion of a packet.
    pub const FIRST: u8 = 0b01;
    /// Sequence Flags: continuing portion of a packet.
    pub const CONTINUING: u8 = 0b00;
    /// Sequence Flags: last portion of a packet.
    pub const LAST: u8 = 0b10;
    /// Sequence Flags: one or more complete packets.
    pub const UNSEGMENTED: u8 = 0b11;

    /// Decodes the header from its raw octet.
    pub fn decode(octet: u8) -> Self {
        TcSegmentHeader {
            sequence_flags: octet >> 6,
            map_id: octet & 0x3f,
        }
    }

    /// The raw octet of the header.
    pub fn octet(&self) -> u8 {
        (self.sequence_flags << 6) | self.map_id
    }

    /// Meaning of the Sequence Flags.
    pub fn sequence_flags_note(&self) -> &'static str {
        match self.sequence_flags {
            Self::FIRST => "first segment",
            Self::CONTINUING => "continuing segment",
            Self::LAST => "last segment",
            _ => "unsegmented",
        }
    }
}

/// A complete, valid TC Transfer Frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcFrame {
    /// Byte offset of the frame within the input stream.
    pub offset: usize,
    /// Raw octets of the Transfer Frame Primary Header.
    pub header_bytes: Vec<u8>,
    /// Decoded Transfer Frame Primary Header.
    pub header: TcPrimaryHeader,
    /// Segment Header, if configured and the frame carries data.
    pub segment_header: Option<TcSegmentHeader>,
    /// Raw octets of the Security Header, if configured and the frame
    /// carries data.
    pub security_header: Option<Vec<u8>>,
    /// Transfer Frame Data Field (without Segment Header and security fields).
    pub data: Vec<u8>,
    /// Raw octets of the Security Trailer, if configured and the frame
    /// carries data.
    pub security_trailer: Option<Vec<u8>>,
    /// Frame Error Control Field, if configured.
    pub fecf: Option<Fecf>,
}

impl TcFrame {
    /// Title of the frame, e.g. `"TC Transfer Frame SCID=42 VCID=1"`.
    pub fn title(&self) -> String {
        format!(
            "TC Transfer Frame SCID={} VCID={}",
            self.header.spacecraft_id, self.header.virtual_channel_id
        )
    }

    /// Short identification, e.g. `"SCID=42 VCID=1 AD N(S)=3"`.
    pub fn identification(&self) -> String {
        format!(
            "SCID={} VCID={} {} N(S)={}",
            self.header.spacecraft_id,
            self.header.virtual_channel_id,
            self.header.frame_type(),
            self.header.frame_sequence_number
        )
    }

    /// Byte offset of the first Transfer Frame Data Field octet in the input
    /// stream.
    pub fn data_offset(&self) -> usize {
        self.offset
            + TC_PRIMARY_HEADER_LEN
            + self.segment_header.map_or(0, |_| SEGMENT_HEADER_LEN)
            + self.security_header.as_ref().map_or(0, Vec::len)
    }

    /// Name of the control command in the data field of a Type-C frame.
    pub fn control_command(&self) -> Option<&'static str> {
        if !self.header.is_control() {
            return None;
        }
        Some(match self.data.as_slice() {
            [0x00] => "Unlock",
            [0x82, 0x00, _] => "Set V(R)",
            _ => "unknown control command",
        })
    }
}

/// Result of parsing a stream of TC frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcFrameStream {
    /// Name of the input (usually the file name).
    pub source: String,
    /// Configuration used for parsing.
    pub config: TcFrameConfig,
    /// All valid frames in stream order.
    pub frames: Vec<TcFrame>,
    /// The first invalid frame, if the stream does not end cleanly.
    pub invalid: Option<InvalidData>,
    /// Space Packets extracted from the data fields of the valid frames.
    pub extraction: PacketExtraction,
}

impl TcFrameStream {
    /// Parses a stream given as hex text (see [`crate::hex`] for the format).
    pub fn from_hex_text(source: impl Into<String>, text: &str, config: TcFrameConfig) -> Self {
        let (bytes, hex_error) = parse_hex_text(text);
        let mut stream = parse_tc_frame_stream(source, &bytes, config);
        if let Some(hex_error) = hex_error {
            merge_hex_error(&mut stream.invalid, &hex_error, bytes.len());
        }
        stream
    }
}

/// Splits a raw byte stream into consecutive TC Transfer Frames.
///
/// Parsing stops at the first frame that is not valid. A frame is valid if
/// - at least the 5 octets of the Transfer Frame Primary Header are available,
/// - the Transfer Frame Version Number is `0` (binary `00`),
/// - the complete frame (Frame Length + 1 octets) is available,
/// - Segment Header, security fields and FECF (as far as configured) leave
///   room for at least one octet of Transfer Frame Data Field, and
/// - the FECF matches the computed CRC (if configured and checked).
pub fn parse_tc_frame_stream(
    source: impl Into<String>,
    bytes: &[u8],
    config: TcFrameConfig,
) -> TcFrameStream {
    let mut frames = Vec::new();
    let mut invalid = None;
    let mut offset = 0usize;

    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        match parse_tc_frame(remaining, offset, &config) {
            Ok(frame) => {
                offset += frame.header.total_length();
                frames.push(frame);
            }
            Err(reason) => {
                invalid = Some(InvalidData {
                    offset,
                    reason,
                    remaining_len: remaining.len(),
                });
                break;
            }
        }
    }

    // Packets cannot be found in an encrypted data field.
    let encrypted = matches!(&config.sdls, Some(sdls) if sdls.encrypted);
    let extraction = if encrypted {
        PacketExtraction::default()
    } else {
        extract_tc_packets(&frames)
    };
    TcFrameStream {
        source: source.into(),
        config,
        frames,
        invalid,
        extraction,
    }
}

/// Parses one frame at the start of `bytes`.
fn parse_tc_frame(bytes: &[u8], offset: usize, config: &TcFrameConfig) -> Result<TcFrame, String> {
    let Some(header_bytes) = bytes.first_chunk::<TC_PRIMARY_HEADER_LEN>() else {
        return Err(format!(
            "Transfer Frame Primary Header needs {TC_PRIMARY_HEADER_LEN} octets, only {} available",
            bytes.len()
        ));
    };
    let header = TcPrimaryHeader::decode(header_bytes);
    if header.version != 0 {
        return Err(format!(
            "unsupported Transfer Frame Version Number {} (expected 0)",
            header.version
        ));
    }

    let frame_length = header.total_length();
    if bytes.len() < frame_length {
        return Err(format!(
            "Frame Length announces {frame_length} octets, only {} available",
            bytes.len()
        ));
    }
    let frame_bytes = &bytes[..frame_length];

    // Frames with control commands have no Segment Header and are not
    // protected by the Space Data Link Security Protocol.
    let carries_data = !header.is_control();
    let sdls = config.sdls.as_ref().filter(|_| carries_data);
    let segment_header_len = if config.segment_header && carries_data {
        SEGMENT_HEADER_LEN
    } else {
        0
    };
    let security_header_len = sdls.map_or(0, |sdls| sdls.header_length);
    let security_trailer_len = sdls.map_or(0, |sdls| sdls.trailer_length);
    let fecf_len = if config.fecf_present { FECF_LEN } else { 0 };

    let security_start = TC_PRIMARY_HEADER_LEN + segment_header_len;
    let data_start = security_start + security_header_len;
    let fecf_start = frame_length.saturating_sub(fecf_len);
    let data_end = fecf_start.saturating_sub(security_trailer_len);
    if data_start >= data_end {
        return Err(format!(
            "frame of {frame_length} octets is too short for header, trailer and data field"
        ));
    }

    let fecf = config.fecf_present.then(|| Fecf {
        value: u16::from_be_bytes([frame_bytes[fecf_start], frame_bytes[fecf_start + 1]]),
        computed: crc16_ccitt(&frame_bytes[..fecf_start]),
    });
    if let Some(fecf) = fecf {
        if config.check_crc && !fecf.is_ok() {
            return Err(format!(
                "Frame Error Control Field 0x{:04x} does not match computed CRC 0x{:04x}",
                fecf.value, fecf.computed
            ));
        }
    }

    Ok(TcFrame {
        offset,
        header_bytes: header_bytes.to_vec(),
        header,
        segment_header: (segment_header_len > 0)
            .then(|| TcSegmentHeader::decode(frame_bytes[TC_PRIMARY_HEADER_LEN])),
        security_header: sdls.map(|_| frame_bytes[security_start..data_start].to_vec()),
        data: frame_bytes[data_start..data_end].to_vec(),
        security_trailer: (security_trailer_len > 0)
            .then(|| frame_bytes[data_end..fecf_start].to_vec()),
        fecf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(segment_header: bool, fecf_present: bool) -> TcFrameConfig {
        TcFrameConfig {
            segment_header,
            fecf_present,
            check_crc: true,
            sdls: None,
        }
    }

    /// Builds a frame for SCID 42, VCID 1 with the given flags, sequence
    /// number and content after the primary header; FECF appended if
    /// requested.
    fn build_frame(bypass: bool, control: bool, seq: u8, body: &[u8], fecf: bool) -> Vec<u8> {
        let total = TC_PRIMARY_HEADER_LEN + body.len() + if fecf { FECF_LEN } else { 0 };
        let word0: u16 = (u16::from(bypass) << 13) | (u16::from(control) << 12) | 42;
        let word1: u16 = (1 << 10) | (total as u16 - 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&word0.to_be_bytes());
        frame.extend_from_slice(&word1.to_be_bytes());
        frame.push(seq);
        frame.extend_from_slice(body);
        if fecf {
            let crc = crc16_ccitt(&frame);
            frame.extend_from_slice(&crc.to_be_bytes());
        }
        frame
    }

    #[test]
    fn decodes_primary_header() {
        let header = TcPrimaryHeader::decode(&[0x30, 0x2a, 0x1c, 0x0b, 0x07]);
        assert_eq!(header.version, 0);
        assert_eq!(header.bypass_flag, 1);
        assert_eq!(header.control_command_flag, 1);
        assert_eq!(header.spare, 0);
        assert_eq!(header.spacecraft_id, 42);
        assert_eq!(header.virtual_channel_id, 7);
        assert_eq!(header.frame_length, 11);
        assert_eq!(header.total_length(), 12);
        assert_eq!(header.frame_sequence_number, 7);
        assert_eq!(header.frame_type(), "BC");
        assert!(header.is_control());
    }

    #[test]
    fn decodes_segment_header() {
        let header = TcSegmentHeader::decode(0x45);
        assert_eq!(header.sequence_flags, TcSegmentHeader::FIRST);
        assert_eq!(header.map_id, 5);
        assert_eq!(header.octet(), 0x45);
        assert_eq!(header.sequence_flags_note(), "first segment");
        assert_eq!(
            TcSegmentHeader::decode(0xc1).sequence_flags_note(),
            "unsegmented"
        );
    }

    #[test]
    fn parses_frames_of_different_length() {
        let mut bytes = build_frame(false, false, 0, &[0xc2, 0x11, 0x22, 0x33], true);
        bytes.extend(build_frame(true, false, 0, &[0xc3, 0x44], true));
        let stream = parse_tc_frame_stream("t", &bytes, config(true, true));
        assert_eq!(stream.invalid, None);
        assert_eq!(stream.frames.len(), 2);

        let first = &stream.frames[0];
        assert_eq!(first.title(), "TC Transfer Frame SCID=42 VCID=1");
        assert_eq!(first.identification(), "SCID=42 VCID=1 AD N(S)=0");
        assert_eq!(first.segment_header.unwrap().map_id, 2);
        assert_eq!(first.data, vec![0x11, 0x22, 0x33]);
        assert_eq!(first.data_offset(), 6);
        assert!(first.fecf.unwrap().is_ok());

        let second = &stream.frames[1];
        assert_eq!(second.offset, 11);
        assert_eq!(second.header.frame_type(), "BD");
        assert_eq!(second.data, vec![0x44]);
    }

    #[test]
    fn control_frames_have_no_segment_header_and_no_security_fields() {
        let bytes = build_frame(true, true, 0, &[0x82, 0x00, 0x05], true);
        let mut cfg = config(true, true);
        cfg.sdls = Some(SdlsConfig {
            header_length: 6,
            trailer_length: 8,
            encrypted: false,
        });
        let stream = parse_tc_frame_stream("t", &bytes, cfg);
        let frame = &stream.frames[0];
        assert_eq!(frame.segment_header, None);
        assert_eq!(frame.security_header, None);
        assert_eq!(frame.security_trailer, None);
        assert_eq!(frame.data, vec![0x82, 0x00, 0x05]);
        assert_eq!(frame.control_command(), Some("Set V(R)"));

        let unlock = build_frame(true, true, 0, &[0x00], false);
        let stream = parse_tc_frame_stream("t", &unlock, config(false, false));
        assert_eq!(stream.frames[0].control_command(), Some("Unlock"));
    }

    #[test]
    fn parses_security_header_and_trailer() {
        // Segment Header, Security Header (4), data (3), Security Trailer (2).
        let body = [0xc1, 0x00, 0x05, 0x00, 0x01, 0xd1, 0xd2, 0xd3, 0xe1, 0xe2];
        let bytes = build_frame(false, false, 3, &body, true);
        let mut cfg = config(true, true);
        cfg.sdls = Some(SdlsConfig {
            header_length: 4,
            trailer_length: 2,
            encrypted: false,
        });
        let stream = parse_tc_frame_stream("t", &bytes, cfg);
        assert_eq!(stream.invalid, None);
        let frame = &stream.frames[0];
        assert_eq!(frame.segment_header.unwrap().octet(), 0xc1);
        assert_eq!(frame.security_header, Some(vec![0x00, 0x05, 0x00, 0x01]));
        assert_eq!(frame.data, vec![0xd1, 0xd2, 0xd3]);
        assert_eq!(frame.data_offset(), 5 + 1 + 4);
        assert_eq!(frame.security_trailer, Some(vec![0xe1, 0xe2]));
        assert_eq!(frame.control_command(), None);
    }

    #[test]
    fn detects_crc_error() {
        let mut bytes = build_frame(false, false, 0, &[0x11, 0x22, 0x33], true);
        bytes[6] ^= 0x01;
        let stream = parse_tc_frame_stream("t", &bytes, config(false, true));
        assert!(stream.frames.is_empty());
        assert!(stream
            .invalid
            .unwrap()
            .reason
            .contains("Frame Error Control"));

        let mut lenient = config(false, true);
        lenient.check_crc = false;
        let stream = parse_tc_frame_stream("t", &bytes, lenient);
        assert_eq!(stream.frames.len(), 1);
        assert!(!stream.frames[0].fecf.unwrap().is_ok());
    }

    #[test]
    fn reports_truncated_and_too_short_frames() {
        let bytes = build_frame(false, false, 0, &[0x11, 0x22, 0x33], false);
        let stream = parse_tc_frame_stream("t", &bytes[..6], config(false, false));
        assert!(stream.invalid.unwrap().reason.contains("only 6"));

        let stream = parse_tc_frame_stream("t", &bytes[..3], config(false, false));
        assert!(stream.invalid.unwrap().reason.contains("Primary Header"));

        // 8 octets: header, segment header and FECF leave no data octet.
        let stream = parse_tc_frame_stream("t", &bytes, config(true, true));
        assert!(stream.invalid.unwrap().reason.contains("too short"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = build_frame(false, false, 0, &[0x11], false);
        bytes[0] |= 0x40;
        let stream = parse_tc_frame_stream("t", &bytes, config(false, false));
        assert!(stream.invalid.unwrap().reason.contains("Version Number 1"));
    }
}
