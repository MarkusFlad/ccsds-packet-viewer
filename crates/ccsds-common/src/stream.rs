//! The content delivered from the command line application to the web
//! frontend: either a stream of Space Packets or a stream of TM frames.

use serde::{Deserialize, Serialize};

use crate::frame::FrameStream;
use crate::packet::{InvalidData, PacketStream};

/// A parsed input stream of one of the supported kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stream {
    /// CCSDS Space Packets (CCSDS 133.0-B).
    Packets(PacketStream),
    /// CCSDS TM Transfer Frames (CCSDS 132.0-B).
    TmFrames(FrameStream),
}

impl Stream {
    /// Name of the input (usually the file name).
    pub fn source(&self) -> &str {
        match self {
            Stream::Packets(stream) => &stream.source,
            Stream::TmFrames(stream) => &stream.source,
        }
    }

    /// Number of valid items (packets or frames).
    pub fn len(&self) -> usize {
        match self {
            Stream::Packets(stream) => stream.packets.len(),
            Stream::TmFrames(stream) => stream.frames.len(),
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
        }
    }

    /// Text of the red frame marking the first invalid item.
    pub fn invalid_text(&self) -> &'static str {
        match self {
            Stream::Packets(_) => "No valid Packet-Data",
            Stream::TmFrames(_) => "No valid Frame-Data",
        }
    }

    /// The first invalid item, if any.
    pub fn invalid(&self) -> Option<&InvalidData> {
        match self {
            Stream::Packets(stream) => stream.invalid.as_ref(),
            Stream::TmFrames(stream) => stream.invalid.as_ref(),
        }
    }
}
