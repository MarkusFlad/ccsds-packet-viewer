//! Shared building blocks for the CCSDS Space Packet viewer.
//!
//! Supported inputs: CCSDS Space Packets ([`packet`]) and CCSDS TM Transfer
//! Frames ([`frame`]); [`Stream`] wraps either of them.
//!
//! This crate is used by both the native command line application (which
//! parses the input file) and the WebAssembly frontend (which renders the
//! packets). Keeping the data model and all number formatting in one place
//! guarantees that both sides agree on how a packet looks.
//!
//! The packet layout follows CCSDS 133.0-B-2 "Space Packet Protocol":
//!
//! ```text
//! +---------+------------------------------+------------------------------+-------------+
//! | Version | Packet Identification        | Packet Sequence Control      | Packet Data |
//! |         +------+-----------+-----------+-----------+------------------+ Length      |
//! |         | Type | Sec. Hdr. | APID      | Sequence  | Sequence Count   |             |
//! |         |      | Flag      |           | Flags     | or Packet Name   |             |
//! | 3 bits  | 1    | 1         | 11 bits   | 2 bits    | 14 bits          | 16 bits     |
//! +---------+------+-----------+-----------+-----------+------------------+-------------+
//! |<-------------------- Packet Primary Header (6 bytes) --------------------------------->|
//! followed by the Packet Data Field (1 to 65536 bytes).
//! ```

pub mod crc;
pub mod extract;
pub mod frame;
pub mod hex;
pub mod packet;
pub mod stream;

pub use extract::{extract_packets, DataSpan, ExtractedPacket, PacketExtraction, SpanKind};
pub use frame::{
    parse_frame_stream, Fecf, FrameStream, TmFrame, TmFrameConfig, TmPrimaryHeader,
    TmSecondaryHeader, DEFAULT_ASM,
};
pub use hex::{format_hex_bytes, format_hex_value, parse_hex_text, HexParseError};
pub use packet::{
    parse_packet_stream, FieldValue, InvalidData, PacketStream, PacketType, PrimaryHeader,
    SpacePacket, PRIMARY_HEADER_LEN,
};
pub use stream::Stream;
