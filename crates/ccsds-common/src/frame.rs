//! CCSDS TM Transfer Frame data model and stream parser
//! (CCSDS 132.0-B-3 "TM Space Data Link Protocol").
//!
//! ```text
//! +-------------------+---------------------+----------------+--------------------+
//! | Transfer Frame    | Transfer Frame      | Transfer Frame | Transfer Frame     |
//! | Primary Header    | Secondary Header    | Data Field     | Trailer            |
//! | (6 octets)        | (optional, 1..64)   |                | (optional OCF 4 +  |
//! |                   |                     |                |  optional FECF 2)  |
//! +-------------------+---------------------+----------------+--------------------+
//! ```
//!
//! Primary header bit layout:
//!
//! ```text
//! | Master Channel ID      | VCID | OCF  | MC Frame | VC Frame | Transfer Frame Data Field Status          |
//! | Version | Spacecraft ID|      | Flag | Count    | Count    | SecHdr | Sync | Pkt Order | Seg.Len | FHP |
//! | 2       | 10           | 3    | 1    | 8        | 8        | 1      | 1    | 1         | 2       | 11  |
//! ```
//!
//! The frame length and the presence of the Frame Error Control Field are
//! managed parameters of the physical/master channel; they are not contained
//! in the frame and therefore have to be configured ([`TmFrameConfig`]).
//! The presence of the Secondary Header and of the Operational Control Field
//! is signalled by flags in the primary header.
//!
//! With the Space Data Link Security Protocol (CCSDS 355.0-B-2) a Security
//! Header precedes and an optional Security Trailer follows the Transfer
//! Frame Data Field:
//!
//! ```text
//! +---------+-----------+----------+----------------+----------+-----+------+
//! | Primary | Secondary | Security | Transfer Frame | Security | OCF | FECF |
//! | Header  | Header    | Header   | Data Field     | Trailer  |     |      |
//! +---------+-----------+----------+----------------+----------+-----+------+
//! ```
//!
//! The lengths of both are managed parameters of the Security Association
//! as well ([`SdlsConfig`]). Their content (Security Parameter Index,
//! Initialization Vector, Sequence Number, Pad Length, Message
//! Authentication Code) is not decoded.

use serde::{Deserialize, Serialize};

use crate::crc::crc16_ccitt;
use crate::extract::{extract_packets, PacketExtraction};
use crate::hex::parse_hex_text;
use crate::packet::{merge_hex_error, InvalidData};

/// Length of the Transfer Frame Primary Header in octets.
pub const TM_PRIMARY_HEADER_LEN: usize = 6;
/// Length of the Operational Control Field in octets.
pub const OCF_LEN: usize = 4;
/// Length of the Frame Error Control Field in octets.
pub const FECF_LEN: usize = 2;
/// Maximum length of a TM Transfer Frame in octets.
pub const MAX_FRAME_LEN: usize = 2048;
/// Maximum length of the Transfer Frame Secondary Header in octets.
pub const MAX_SECONDARY_HEADER_LEN: usize = 64;
/// Minimum length of the Security Header in octets: it always starts with
/// the 2 octet Security Parameter Index.
pub const MIN_SECURITY_HEADER_LEN: usize = 2;
/// The standard Attached Sync Marker for TM (CCSDS 131.0-B).
pub const DEFAULT_ASM: [u8; 4] = [0x1a, 0xcf, 0xfc, 0x1d];

/// First Header Pointer value: no packet starts in this frame.
pub const FHP_NO_PACKET_START: u16 = 0x7ff;
/// First Header Pointer value: the data field contains only idle data.
pub const FHP_IDLE_DATA: u16 = 0x7fe;

/// Managed parameters needed to split a byte stream into TM frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TmFrameConfig {
    /// Total length of every Transfer Frame in octets (without ASM).
    pub frame_length: usize,
    /// Every frame ends with a 2 octet Frame Error Control Field.
    pub fecf_present: bool,
    /// If `false`, a FECF mismatch is shown but does not make the frame invalid.
    pub check_crc: bool,
    /// Attached Sync Marker in front of every frame, if any.
    pub asm: Option<Vec<u8>>,
    /// Space Data Link Security Protocol fields in every frame, if any.
    pub sdls: Option<SdlsConfig>,
}

/// Managed parameters of the Security Association: the lengths of the
/// Space Data Link Security Protocol fields (CCSDS 355.0-B-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdlsConfig {
    /// Length of the Security Header in octets.
    pub header_length: usize,
    /// Length of the Security Trailer in octets; `0` if there is none.
    pub trailer_length: usize,
    /// The Transfer Frame Data Field is encrypted: no packets are extracted.
    pub encrypted: bool,
}

impl TmFrameConfig {
    /// Smallest frame that can hold the primary header, the security and
    /// trailer fields that may be present and at least one data octet.
    pub fn min_frame_length(&self) -> usize {
        let sdls_len = self
            .sdls
            .as_ref()
            .map_or(0, |sdls| sdls.header_length + sdls.trailer_length);
        TM_PRIMARY_HEADER_LEN
            + sdls_len
            + OCF_LEN
            + if self.fecf_present { FECF_LEN } else { 0 }
            + 1
    }

    /// Checks the configuration, returning a human readable error.
    pub fn validate(&self) -> Result<(), String> {
        if self.frame_length < self.min_frame_length() || self.frame_length > MAX_FRAME_LEN {
            return Err(format!(
                "frame length {} out of range ({}..={} octets)",
                self.frame_length,
                self.min_frame_length(),
                MAX_FRAME_LEN
            ));
        }
        if matches!(&self.asm, Some(asm) if asm.is_empty()) {
            return Err("attached sync marker must not be empty".to_string());
        }
        if matches!(&self.sdls, Some(sdls) if sdls.header_length < MIN_SECURITY_HEADER_LEN) {
            return Err(format!(
                "Security Header must be at least {MIN_SECURITY_HEADER_LEN} octets long \
                 (Security Parameter Index)"
            ));
        }
        Ok(())
    }
}

/// Decoded fields of the 6 octet Transfer Frame Primary Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TmPrimaryHeader {
    /// Transfer Frame Version Number (2 bits).
    pub version: u8,
    /// Spacecraft Identifier (10 bits).
    pub spacecraft_id: u16,
    /// Virtual Channel Identifier (3 bits).
    pub virtual_channel_id: u8,
    /// Operational Control Field Flag (1 bit).
    pub ocf_flag: u8,
    /// Master Channel Frame Count (8 bits).
    pub mc_frame_count: u8,
    /// Virtual Channel Frame Count (8 bits).
    pub vc_frame_count: u8,
    /// Transfer Frame Secondary Header Flag (1 bit).
    pub secondary_header_flag: u8,
    /// Synchronization Flag (1 bit).
    pub sync_flag: u8,
    /// Packet Order Flag (1 bit).
    pub packet_order_flag: u8,
    /// Segment Length Identifier (2 bits).
    pub segment_length_id: u8,
    /// First Header Pointer (11 bits).
    pub first_header_pointer: u16,
}

impl TmPrimaryHeader {
    pub const VERSION_BITS: u32 = 2;
    pub const SPACECRAFT_ID_BITS: u32 = 10;
    pub const VIRTUAL_CHANNEL_ID_BITS: u32 = 3;
    pub const OCF_FLAG_BITS: u32 = 1;
    pub const MC_FRAME_COUNT_BITS: u32 = 8;
    pub const VC_FRAME_COUNT_BITS: u32 = 8;
    pub const SECONDARY_HEADER_FLAG_BITS: u32 = 1;
    pub const SYNC_FLAG_BITS: u32 = 1;
    pub const PACKET_ORDER_FLAG_BITS: u32 = 1;
    pub const SEGMENT_LENGTH_ID_BITS: u32 = 2;
    pub const FIRST_HEADER_POINTER_BITS: u32 = 11;
    pub const MASTER_CHANNEL_ID_BITS: u32 = 12;
    pub const DATA_FIELD_STATUS_BITS: u32 = 16;

    /// Decodes the header from its 6 raw octets.
    pub fn decode(bytes: &[u8; TM_PRIMARY_HEADER_LEN]) -> Self {
        let word0 = u16::from_be_bytes([bytes[0], bytes[1]]);
        let status = u16::from_be_bytes([bytes[4], bytes[5]]);

        TmPrimaryHeader {
            version: ((word0 >> 14) & 0x03) as u8,
            spacecraft_id: (word0 >> 4) & 0x03ff,
            virtual_channel_id: ((word0 >> 1) & 0x07) as u8,
            ocf_flag: (word0 & 0x01) as u8,
            mc_frame_count: bytes[2],
            vc_frame_count: bytes[3],
            secondary_header_flag: ((status >> 15) & 0x01) as u8,
            sync_flag: ((status >> 14) & 0x01) as u8,
            packet_order_flag: ((status >> 13) & 0x01) as u8,
            segment_length_id: ((status >> 11) & 0x03) as u8,
            first_header_pointer: status & 0x07ff,
        }
    }

    /// The 12 bit Master Channel Identifier (Version Number and Spacecraft ID).
    pub fn master_channel_id(&self) -> u16 {
        (u16::from(self.version) << 10) | self.spacecraft_id
    }

    /// The 16 bit Transfer Frame Data Field Status.
    pub fn data_field_status(&self) -> u16 {
        (u16::from(self.secondary_header_flag) << 15)
            | (u16::from(self.sync_flag) << 14)
            | (u16::from(self.packet_order_flag) << 13)
            | (u16::from(self.segment_length_id) << 11)
            | self.first_header_pointer
    }

    /// Meaning of special First Header Pointer values, if any.
    pub fn first_header_pointer_note(&self) -> Option<&'static str> {
        match self.first_header_pointer {
            FHP_NO_PACKET_START => Some("no packet start"),
            FHP_IDLE_DATA => Some("idle data only"),
            _ => None,
        }
    }
}

/// The optional Transfer Frame Secondary Header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TmSecondaryHeader {
    /// Raw octets (identification octet plus data field).
    pub bytes: Vec<u8>,
    /// Transfer Frame Secondary Header Version Number (2 bits).
    pub version: u8,
    /// Transfer Frame Secondary Header Length (6 bits): total length minus one.
    pub length: u8,
    /// Transfer Frame Secondary Header Data Field.
    pub data: Vec<u8>,
}

impl TmSecondaryHeader {
    pub const VERSION_BITS: u32 = 2;
    pub const LENGTH_BITS: u32 = 6;
    pub const IDENTIFICATION_BITS: u32 = 8;

    /// The 8 bit Transfer Frame Secondary Header Identification field.
    pub fn identification(&self) -> u8 {
        (self.version << 6) | self.length
    }
}

/// The Frame Error Control Field and the CRC computed over the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fecf {
    /// Value transmitted in the frame.
    pub value: u16,
    /// Value computed over the frame.
    pub computed: u16,
}

impl Fecf {
    pub const BITS: u32 = 16;

    /// `true` if the transmitted and the computed CRC match.
    pub fn is_ok(&self) -> bool {
        self.value == self.computed
    }
}

/// A complete, valid TM Transfer Frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TmFrame {
    /// Byte offset of the frame (after a possible ASM) within the input stream.
    pub offset: usize,
    /// Raw octets of the Transfer Frame Primary Header.
    pub header_bytes: Vec<u8>,
    /// Decoded Transfer Frame Primary Header.
    pub header: TmPrimaryHeader,
    /// Transfer Frame Secondary Header, if the flag is set.
    pub secondary_header: Option<TmSecondaryHeader>,
    /// Raw octets of the Security Header, if configured.
    pub security_header: Option<Vec<u8>>,
    /// Transfer Frame Data Field.
    pub data: Vec<u8>,
    /// Raw octets of the Security Trailer, if configured.
    pub security_trailer: Option<Vec<u8>>,
    /// Raw octets of the Transfer Frame Trailer (OCF and/or FECF).
    pub trailer_bytes: Vec<u8>,
    /// Operational Control Field, if the OCF flag is set.
    pub ocf: Option<u32>,
    /// Frame Error Control Field, if configured.
    pub fecf: Option<Fecf>,
}

impl TmFrame {
    pub const OCF_BITS: u32 = 32;

    /// Title of the frame, e.g. `"TM Transfer Frame SCID=42 VCID=1"`.
    pub fn title(&self) -> String {
        format!(
            "TM Transfer Frame SCID={} VCID={}",
            self.header.spacecraft_id, self.header.virtual_channel_id
        )
    }

    /// Byte offset of the first Transfer Frame Data Field octet in the input
    /// stream.
    pub fn data_offset(&self) -> usize {
        self.offset
            + TM_PRIMARY_HEADER_LEN
            + self
                .secondary_header
                .as_ref()
                .map_or(0, |sec| sec.bytes.len())
            + self.security_header.as_ref().map_or(0, Vec::len)
    }

    /// Short identification, e.g. `"SCID=42 VCID=1 MCFC=0 VCFC=0"`.
    pub fn identification(&self) -> String {
        format!(
            "SCID={} VCID={} MCFC={} VCFC={}",
            self.header.spacecraft_id,
            self.header.virtual_channel_id,
            self.header.mc_frame_count,
            self.header.vc_frame_count
        )
    }

    /// `true` if the frame has a trailer (OCF and/or FECF).
    pub fn has_trailer(&self) -> bool {
        !self.trailer_bytes.is_empty()
    }
}

/// Result of parsing a stream of TM frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameStream {
    /// Name of the input (usually the file name).
    pub source: String,
    /// Configuration used for parsing.
    pub config: TmFrameConfig,
    /// All valid frames in stream order.
    pub frames: Vec<TmFrame>,
    /// The first invalid frame, if the stream does not end cleanly.
    pub invalid: Option<InvalidData>,
    /// Space Packets reassembled from the data fields of the valid frames.
    pub extraction: PacketExtraction,
}

impl FrameStream {
    /// Parses a stream given as hex text (see [`crate::hex`] for the format).
    pub fn from_hex_text(source: impl Into<String>, text: &str, config: TmFrameConfig) -> Self {
        let (bytes, hex_error) = parse_hex_text(text);
        let mut stream = parse_frame_stream(source, &bytes, config);
        if let Some(hex_error) = hex_error {
            merge_hex_error(&mut stream.invalid, &hex_error, bytes.len());
        }
        stream
    }
}

/// Splits a raw byte stream into consecutive TM Transfer Frames.
///
/// Parsing stops at the first frame that is not valid. A frame is valid if
/// - the Attached Sync Marker matches (if configured),
/// - the complete frame (configured frame length) is available,
/// - the Transfer Frame Version Number is `0` (binary `00`),
/// - the Secondary Header (if flagged), the security fields (if configured)
///   and the trailer leave room for at least one octet of Transfer Frame
///   Data Field, and
/// - the FECF matches the computed CRC (if configured and checked).
pub fn parse_frame_stream(
    source: impl Into<String>,
    bytes: &[u8],
    config: TmFrameConfig,
) -> FrameStream {
    let mut frames = Vec::new();
    let mut invalid = None;
    let mut offset = 0usize;
    let asm_len = config.asm.as_ref().map_or(0, Vec::len);

    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        match parse_frame(remaining, offset, asm_len, &config) {
            Ok(frame) => {
                frames.push(frame);
                offset += asm_len + config.frame_length;
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
        extract_packets(&frames)
    };
    FrameStream {
        source: source.into(),
        config,
        frames,
        invalid,
        extraction,
    }
}

/// Parses one frame (including a possible ASM) at the start of `bytes`.
fn parse_frame(
    bytes: &[u8],
    offset: usize,
    asm_len: usize,
    config: &TmFrameConfig,
) -> Result<TmFrame, String> {
    if let Some(asm) = &config.asm {
        if bytes.len() < asm.len() || &bytes[..asm.len()] != asm.as_slice() {
            return Err(format!(
                "Attached Sync Marker {} not found",
                crate::hex::format_hex_bytes(asm)
            ));
        }
    }

    if config.frame_length < config.min_frame_length() {
        return Err(format!("frame length {} is too small", config.frame_length));
    }

    let frame_bytes = &bytes[asm_len..];
    if frame_bytes.len() < config.frame_length {
        return Err(format!(
            "frame length is {} octets, only {} available",
            config.frame_length,
            frame_bytes.len()
        ));
    }
    let frame_bytes = &frame_bytes[..config.frame_length];

    let header_bytes: &[u8; TM_PRIMARY_HEADER_LEN] = frame_bytes
        .first_chunk()
        .expect("frame length is at least the header length");
    let header = TmPrimaryHeader::decode(header_bytes);
    if header.version != 0 {
        return Err(format!(
            "unsupported Transfer Frame Version Number {} (expected 0)",
            header.version
        ));
    }

    // Layout from the end of the frame: [Security Trailer][OCF][FECF].
    let fecf_len = if config.fecf_present { FECF_LEN } else { 0 };
    let ocf_len = if header.ocf_flag == 1 { OCF_LEN } else { 0 };
    let security_trailer_len = config.sdls.as_ref().map_or(0, |sdls| sdls.trailer_length);
    let trailer_start = config.frame_length - fecf_len - ocf_len;
    let Some(data_end) = trailer_start.checked_sub(security_trailer_len) else {
        return Err("frame too short for the Security Trailer".to_string());
    };

    let mut data_start = TM_PRIMARY_HEADER_LEN;
    let secondary_header = if header.secondary_header_flag == 1 {
        let id = frame_bytes[data_start];
        let total_len = usize::from(id & 0x3f) + 1;
        if data_start + total_len >= data_end {
            return Err(format!(
                "Secondary Header of {total_len} octets leaves no room for the data field"
            ));
        }
        let bytes = frame_bytes[data_start..data_start + total_len].to_vec();
        data_start += total_len;
        Some(TmSecondaryHeader {
            version: id >> 6,
            length: id & 0x3f,
            data: bytes[1..].to_vec(),
            bytes,
        })
    } else {
        None
    };

    let security_header = match &config.sdls {
        Some(sdls) => {
            let total_len = sdls.header_length;
            if data_start + total_len >= data_end {
                return Err(format!(
                    "Security Header of {total_len} octets leaves no room for the data field"
                ));
            }
            let bytes = frame_bytes[data_start..data_start + total_len].to_vec();
            data_start += total_len;
            Some(bytes)
        }
        None => None,
    };
    if data_start >= data_end {
        return Err("frame too short for header, trailer and data field".to_string());
    }
    let security_trailer =
        (security_trailer_len > 0).then(|| frame_bytes[data_end..trailer_start].to_vec());

    let ocf = (ocf_len > 0).then(|| {
        let ocf_bytes = &frame_bytes[trailer_start..trailer_start + OCF_LEN];
        u32::from_be_bytes(ocf_bytes.try_into().expect("4 octets"))
    });

    let fecf = config.fecf_present.then(|| {
        let fecf_start = config.frame_length - FECF_LEN;
        Fecf {
            value: u16::from_be_bytes([frame_bytes[fecf_start], frame_bytes[fecf_start + 1]]),
            computed: crc16_ccitt(&frame_bytes[..fecf_start]),
        }
    });
    if let Some(fecf) = fecf {
        if config.check_crc && !fecf.is_ok() {
            return Err(format!(
                "Frame Error Control Field 0x{:04x} does not match computed CRC 0x{:04x}",
                fecf.value, fecf.computed
            ));
        }
    }

    Ok(TmFrame {
        offset: offset + asm_len,
        header_bytes: header_bytes.to_vec(),
        header,
        secondary_header,
        security_header,
        data: frame_bytes[data_start..data_end].to_vec(),
        security_trailer,
        trailer_bytes: frame_bytes[trailer_start..].to_vec(),
        ocf,
        fecf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(frame_length: usize, fecf_present: bool) -> TmFrameConfig {
        TmFrameConfig {
            frame_length,
            fecf_present,
            check_crc: true,
            asm: None,
            sdls: None,
        }
    }

    /// Builds a frame: SCID 42, VCID 1, given OCF flag, optional secondary
    /// header, filled with `fill`, FECF appended if requested.
    fn build_frame(len: usize, ocf: bool, sec: Option<&[u8]>, fecf: bool, fill: u8) -> Vec<u8> {
        let word0: u16 = (42 << 4) | (1 << 1) | u16::from(ocf);
        let status: u16 = (u16::from(sec.is_some()) << 15) | (3 << 11) | 0x7ff;
        let mut frame = Vec::new();
        frame.extend_from_slice(&word0.to_be_bytes());
        frame.extend_from_slice(&[7, 3]);
        frame.extend_from_slice(&status.to_be_bytes());
        if let Some(sec) = sec {
            frame.extend_from_slice(sec);
        }
        let trailer = if ocf { 4 } else { 0 } + if fecf { 2 } else { 0 };
        frame.resize(len - trailer, fill);
        if ocf {
            frame.extend_from_slice(&[0x01, 0x04, 0x00, 0x07]);
        }
        if fecf {
            let crc = crc16_ccitt(&frame);
            frame.extend_from_slice(&crc.to_be_bytes());
        }
        frame
    }

    #[test]
    fn decodes_primary_header() {
        let header = TmPrimaryHeader::decode(&[0x02, 0xa3, 0x07, 0x03, 0x9f, 0xff]);
        assert_eq!(header.version, 0);
        assert_eq!(header.spacecraft_id, 42);
        assert_eq!(header.virtual_channel_id, 1);
        assert_eq!(header.ocf_flag, 1);
        assert_eq!(header.mc_frame_count, 7);
        assert_eq!(header.vc_frame_count, 3);
        assert_eq!(header.secondary_header_flag, 1);
        assert_eq!(header.sync_flag, 0);
        assert_eq!(header.packet_order_flag, 0);
        assert_eq!(header.segment_length_id, 3);
        assert_eq!(header.first_header_pointer, 0x7ff);
        assert_eq!(header.master_channel_id(), 42);
        assert_eq!(header.data_field_status(), 0x9fff);
        assert_eq!(header.first_header_pointer_note(), Some("no packet start"));
    }

    #[test]
    fn parses_frames_with_trailer_and_secondary_header() {
        let mut bytes = build_frame(32, true, None, true, 0xaa);
        bytes.extend(build_frame(
            32,
            false,
            Some(&[0x02, 0x11, 0x22]),
            true,
            0xbb,
        ));
        let stream = parse_frame_stream("t", &bytes, config(32, true));
        assert_eq!(stream.invalid, None);
        assert_eq!(stream.frames.len(), 2);

        let first = &stream.frames[0];
        assert_eq!(first.title(), "TM Transfer Frame SCID=42 VCID=1");
        assert_eq!(first.ocf, Some(0x0104_0007));
        assert!(first.fecf.unwrap().is_ok());
        assert_eq!(first.data.len(), 32 - 6 - 4 - 2);
        assert_eq!(first.trailer_bytes.len(), 6);

        let second = &stream.frames[1];
        assert_eq!(second.offset, 32);
        let sec = second.secondary_header.as_ref().unwrap();
        assert_eq!(sec.length, 2);
        assert_eq!(sec.data, vec![0x11, 0x22]);
        assert_eq!(second.ocf, None);
        assert_eq!(second.data.len(), 32 - 6 - 3 - 2);
    }

    #[test]
    fn detects_crc_error() {
        let mut bytes = build_frame(20, false, None, true, 0x00);
        bytes[10] ^= 0x01;
        let stream = parse_frame_stream("t", &bytes, config(20, true));
        assert!(stream.frames.is_empty());
        assert!(stream
            .invalid
            .unwrap()
            .reason
            .contains("Frame Error Control"));

        let mut lenient = config(20, true);
        lenient.check_crc = false;
        let stream = parse_frame_stream("t", &bytes, lenient);
        assert_eq!(stream.frames.len(), 1);
        assert!(!stream.frames[0].fecf.unwrap().is_ok());
    }

    #[test]
    fn handles_asm() {
        let mut bytes = DEFAULT_ASM.to_vec();
        bytes.extend(build_frame(20, true, None, false, 0x11));
        bytes.extend_from_slice(&[0x1a, 0xcf, 0x00, 0x00]);
        let mut cfg = config(20, false);
        cfg.asm = Some(DEFAULT_ASM.to_vec());
        let stream = parse_frame_stream("t", &bytes, cfg);
        assert_eq!(stream.frames.len(), 1);
        assert_eq!(stream.frames[0].offset, 4);
        let invalid = stream.invalid.unwrap();
        assert_eq!(invalid.offset, 24);
        assert!(invalid.reason.contains("Sync Marker"));
    }

    #[test]
    fn reports_truncated_frame() {
        let bytes = build_frame(20, false, None, false, 0x11);
        let stream = parse_frame_stream("t", &bytes[..15], config(20, false));
        assert!(stream.frames.is_empty());
        assert!(stream.invalid.unwrap().reason.contains("only 15"));
    }

    #[test]
    fn rejects_oversized_secondary_header() {
        // Secondary header claims 64 octets in a 20 octet frame.
        let bytes = build_frame(20, false, Some(&[0x3f]), false, 0x00);
        let stream = parse_frame_stream("t", &bytes, config(20, false));
        assert!(stream.invalid.unwrap().reason.contains("Secondary Header"));
    }

    fn sdls(header_length: usize, trailer_length: usize) -> Option<SdlsConfig> {
        Some(SdlsConfig {
            header_length,
            trailer_length,
            encrypted: false,
        })
    }

    #[test]
    fn parses_security_header_and_trailer() {
        // Secondary header (3 octets), Security Header (8 octets), data,
        // Security Trailer (4 octets), OCF, FECF.
        let sec = [0x02, 0x11, 0x22];
        let security = [0x00, 0x05, 0xa1, 0xa2, 0xa3, 0x00, 0x09, 0x02];
        let mut prefix = sec.to_vec();
        prefix.extend_from_slice(&security);
        let mut bytes = build_frame(40, true, Some(&prefix), false, 0xdd);
        bytes[32..36].copy_from_slice(&[0xc1, 0xc2, 0xc3, 0xc4]);
        let crc = crc16_ccitt(&bytes);
        bytes.extend_from_slice(&crc.to_be_bytes());

        let mut cfg = config(42, true);
        cfg.sdls = sdls(8, 4);
        let stream = parse_frame_stream("t", &bytes, cfg);
        assert_eq!(stream.invalid, None);
        let frame = &stream.frames[0];

        assert_eq!(frame.secondary_header.as_ref().unwrap().bytes, sec);
        assert_eq!(frame.security_header, Some(security.to_vec()));
        assert_eq!(frame.data, vec![0xdd; 40 - 6 - 3 - 8 - 4 - 4]);
        assert_eq!(frame.data_offset(), 6 + 3 + 8);
        assert_eq!(frame.security_trailer, Some(vec![0xc1, 0xc2, 0xc3, 0xc4]));
        assert_eq!(frame.ocf, Some(0x0104_0007));
        assert_eq!(frame.trailer_bytes.len(), 6);
        assert!(frame.fecf.unwrap().is_ok());
    }

    #[test]
    fn security_header_without_trailer() {
        let bytes = build_frame(20, false, None, false, 0x00);
        let mut cfg = config(20, false);
        cfg.sdls = sdls(2, 0);
        let stream = parse_frame_stream("t", &bytes, cfg);
        let frame = &stream.frames[0];
        assert_eq!(frame.security_header.as_ref().unwrap().len(), 2);
        assert_eq!(frame.security_trailer, None);
        assert_eq!(frame.data.len(), 20 - 6 - 2);
    }

    #[test]
    fn encrypted_data_field_is_not_searched_for_packets() {
        // First Header Pointer 0, data field starts with a packet header.
        let mut bytes = build_frame(24, false, None, false, 0x00);
        bytes[4..6].copy_from_slice(&0x1800u16.to_be_bytes());
        bytes[8..14].copy_from_slice(&[0x08, 0x2f, 0xc0, 0x01, 0x00, 0x09]);
        let mut cfg = config(24, false);
        cfg.sdls = sdls(2, 0);
        let clear = parse_frame_stream("t", &bytes, cfg.clone());
        assert_eq!(clear.extraction.complete_count(), 1);

        cfg.sdls.as_mut().unwrap().encrypted = true;
        let encrypted = parse_frame_stream("t", &bytes, cfg);
        assert_eq!(encrypted.frames.len(), 1);
        assert!(encrypted.extraction.packets.is_empty());
        assert!(encrypted.extraction.frame_spans.is_empty());
    }

    #[test]
    fn rejects_security_fields_without_room_for_data() {
        let bytes = build_frame(20, false, None, false, 0x00);
        let mut cfg = config(20, false);
        cfg.sdls = sdls(14, 0);
        assert!(cfg.validate().is_err());
        let stream = parse_frame_stream("t", &bytes, cfg);
        assert!(stream.invalid.unwrap().reason.contains("too small"));
    }

    #[test]
    fn rejects_security_header_shorter_than_the_spi() {
        let mut cfg = config(64, false);
        cfg.sdls = sdls(1, 0);
        assert!(cfg.validate().is_err());
        cfg.sdls = sdls(2, 0);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validates_config() {
        assert!(config(64, true).validate().is_ok());
        assert!(config(5, false).validate().is_err());
        assert!(config(4096, false).validate().is_err());
    }
}
