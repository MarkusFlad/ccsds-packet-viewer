//! The content delivered from the command line application to the web
//! frontend: a stream of Space Packets, of TM frames or of TC frames.

use serde::{Deserialize, Serialize};

use crate::extract::PacketExtraction;
use crate::frame::{FrameStream, SdlsConfig};
use crate::packet::{InvalidData, PacketStream};
use crate::tc_frame::TcFrameStream;

/// A parsed input stream of one of the supported kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stream {
    /// CCSDS Space Packets (CCSDS 133.0-B).
    Packets(PacketStream),
    /// CCSDS TM Transfer Frames (CCSDS 132.0-B).
    TmFrames(FrameStream),
    /// CCSDS TC Transfer Frames (CCSDS 232.0-B).
    TcFrames(TcFrameStream),
}

impl Stream {
    /// Name of the input (usually the file name).
    pub fn source(&self) -> &str {
        match self {
            Stream::Packets(stream) => &stream.source,
            Stream::TmFrames(stream) => &stream.source,
            Stream::TcFrames(stream) => &stream.source,
        }
    }

    /// Number of valid items (packets or frames).
    pub fn len(&self) -> usize {
        match self {
            Stream::Packets(stream) => stream.packets.len(),
            Stream::TmFrames(stream) => stream.frames.len(),
            Stream::TcFrames(stream) => stream.frames.len(),
        }
    }

    /// `true` if the stream contains no valid item.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Plural noun for the items, e.g. for "7 valid packet(s)".
    pub fn item_name(&self) -> &'static str {
        match self {
            Stream::Packets(_) => "packet(s)",
            Stream::TmFrames(_) => "TM frame(s)",
            Stream::TcFrames(_) => "TC frame(s)",
        }
    }

    /// Text of the red frame marking the first invalid item.
    pub fn invalid_text(&self) -> &'static str {
        match self {
            Stream::Packets(_) => "No valid Packet-Data",
            Stream::TmFrames(_) | Stream::TcFrames(_) => "No valid Frame-Data",
        }
    }

    /// Space Packets extracted from the frame data fields (frame streams
    /// only).
    pub fn extraction(&self) -> Option<&PacketExtraction> {
        match self {
            Stream::Packets(_) => None,
            Stream::TmFrames(stream) => Some(&stream.extraction),
            Stream::TcFrames(stream) => Some(&stream.extraction),
        }
    }

    /// Space Data Link Security Protocol parameters, if configured.
    pub fn sdls(&self) -> Option<&SdlsConfig> {
        match self {
            Stream::Packets(_) => None,
            Stream::TmFrames(stream) => stream.config.sdls.as_ref(),
            Stream::TcFrames(stream) => stream.config.sdls.as_ref(),
        }
    }

    /// `true` if the frame data fields are encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.sdls().is_some_and(|sdls| sdls.encrypted)
    }

    /// The first invalid item, if any.
    pub fn invalid(&self) -> Option<&InvalidData> {
        match self {
            Stream::Packets(stream) => stream.invalid.as_ref(),
            Stream::TmFrames(stream) => stream.invalid.as_ref(),
            Stream::TcFrames(stream) => stream.invalid.as_ref(),
        }
    }
}
