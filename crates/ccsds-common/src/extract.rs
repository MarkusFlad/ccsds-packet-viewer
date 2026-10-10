//! Extraction of Space Packets from the data fields of TM Transfer Frames
//! (CCSDS 132.0-B-3, 4.1.4 "Transfer Frame Data Field" and 4.1.2.7
//! "First Header Pointer").
//!
//! Packets are reassembled separately for every virtual channel (Spacecraft
//! ID + Virtual Channel ID), in stream order. A packet may start anywhere in a
//! data field and continue over any number of following frames of the same
//! virtual channel. The First Header Pointer gives the position of the first
//! packet header in a frame; further packets in the same frame are found via
//! the Packet Data Length of their predecessors.
//!
//! The reassembly of a virtual channel is interrupted (the packet in progress
//! is reported as incomplete) by
//! - a gap in the Virtual Channel Frame Count,
//! - a frame with a FECF mismatch (only possible with `--ignore-crc`),
//! - a frame whose data field does not contain packets (Synchronization Flag 1),
//! - a First Header Pointer that contradicts the packet in progress.
//!
//! After an interruption, extraction resumes at the next First Header Pointer.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::frame::{TmFrame, FHP_IDLE_DATA, FHP_NO_PACKET_START};
use crate::packet::{PrimaryHeader, SpacePacket, PRIMARY_HEADER_LEN};

/// What a part of a frame data field belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanKind {
    /// Part of the extracted packet with index `packet`.
    Packet {
        packet: usize,
        /// The packet header starts in this span.
        starts_here: bool,
    },
    /// Idle data (First Header Pointer `0x7fe`).
    Idle,
    /// Data that cannot be assigned to a packet (e.g. the continuation of a
    /// packet whose start was not received).
    Unassigned,
}

/// A contiguous part of a frame data field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSpan {
    /// Start index within the Transfer Frame Data Field.
    pub start: usize,
    /// Number of octets.
    pub len: usize,
    pub kind: SpanKind,
}

/// A packet reassembled from one or more frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedPacket {
    /// Index of the frame in which the packet starts.
    pub first_frame: usize,
    /// Indices of all frames containing parts of the packet.
    pub frames: Vec<usize>,
    /// The packet, if it could be reassembled completely.
    pub packet: Option<SpacePacket>,
    /// Why the packet is incomplete or invalid.
    pub error: Option<String>,
    /// Octets collected so far (used during reassembly).
    #[serde(skip)]
    bytes: Vec<u8>,
    /// Byte offset of the first packet octet in the input stream.
    #[serde(skip)]
    offset: usize,
}

impl ExtractedPacket {
    /// Title of the packet, or a description of the incomplete packet.
    pub fn title(&self) -> String {
        match &self.packet {
            Some(packet) => packet.title(),
            None => "incomplete Space Packet".to_string(),
        }
    }
}

/// Result of the packet extraction for a whole frame stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketExtraction {
    /// All packets in order of their first octet.
    pub packets: Vec<ExtractedPacket>,
    /// For every frame (same index as the frame list): the parts of its data
    /// field and what they belong to.
    pub frame_spans: Vec<Vec<DataSpan>>,
}

impl PacketExtraction {
    /// Packets whose header starts in the given frame.
    pub fn packets_starting_in(&self, frame: usize) -> impl Iterator<Item = &ExtractedPacket> {
        self.packets
            .iter()
            .filter(move |packet| packet.first_frame == frame)
    }

    /// Number of completely reassembled packets.
    pub fn complete_count(&self) -> usize {
        self.packets.iter().filter(|p| p.packet.is_some()).count()
    }
}

/// Reassembly state of one virtual channel.
#[derive(Default)]
struct ChannelState {
    /// Index of the packet currently being reassembled.
    pending: Option<usize>,
    /// Virtual Channel Frame Count of the previous frame.
    last_vc_frame_count: Option<u8>,
}

/// Number of octets still needed to complete the packet in `bytes`.
fn octets_needed(bytes: &[u8]) -> usize {
    if bytes.len() < PRIMARY_HEADER_LEN {
        return PRIMARY_HEADER_LEN - bytes.len();
    }
    let data_length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    PRIMARY_HEADER_LEN + data_length + 1 - bytes.len()
}

/// Version number check on a complete primary header.
fn has_valid_version(bytes: &[u8]) -> bool {
    bytes.len() < PRIMARY_HEADER_LEN || bytes[0] >> 5 == 0
}

/// Appends octets from `data` to the packet until it is complete or `data` is
/// exhausted. Stops early if the header shows an invalid version number.
/// Returns the number of octets taken.
fn feed(packet: &mut ExtractedPacket, data: &[u8]) -> usize {
    let mut used = 0;
    loop {
        if !has_valid_version(&packet.bytes) {
            break;
        }
        let needed = octets_needed(&packet.bytes);
        if needed == 0 || used == data.len() {
            break;
        }
        let take = needed.min(data.len() - used);
        packet.bytes.extend_from_slice(&data[used..used + take]);
        used += take;
    }
    used
}

/// Converts the collected octets into a [`SpacePacket`].
fn finish(packet: &mut ExtractedPacket) {
    let header_bytes: &[u8; PRIMARY_HEADER_LEN] = packet
        .bytes
        .first_chunk()
        .expect("complete packet has a header");
    packet.packet = Some(SpacePacket {
        offset: packet.offset,
        header_bytes: header_bytes.to_vec(),
        header: PrimaryHeader::decode(header_bytes),
        data: packet.bytes[PRIMARY_HEADER_LEN..].to_vec(),
    });
    packet.bytes = Vec::new();
}

/// Marks the packet in progress of a channel as incomplete.
fn abort(packets: &mut [ExtractedPacket], state: &mut ChannelState, reason: String) {
    if let Some(index) = state.pending.take() {
        let packet = &mut packets[index];
        packet.error = Some(format!(
            "{reason} (packet incomplete: {} octet(s) received)",
            packet.bytes.len()
        ));
        packet.bytes = Vec::new();
    }
}

/// Reassembles the Space Packets contained in the given frames.
pub fn extract_packets(frames: &[TmFrame]) -> PacketExtraction {
    let mut packets: Vec<ExtractedPacket> = Vec::new();
    let mut frame_spans: Vec<Vec<DataSpan>> = vec![Vec::new(); frames.len()];
    let mut channels: HashMap<(u16, u8), ChannelState> = HashMap::new();

    for (frame_index, frame) in frames.iter().enumerate() {
        let header = &frame.header;
        let state = channels
            .entry((header.spacecraft_id, header.virtual_channel_id))
            .or_default();
        let spans = &mut frame_spans[frame_index];
        let data = &frame.data;
        let len = data.len();
        let whole = |kind| DataSpan {
            start: 0,
            len,
            kind,
        };

        // Continuity of the virtual channel.
        if let Some(last) = state.last_vc_frame_count {
            let expected = last.wrapping_add(1);
            if header.vc_frame_count != expected {
                abort(
                    &mut packets,
                    state,
                    format!(
                        "Virtual Channel Frame Count gap: expected {expected}, got {}",
                        header.vc_frame_count
                    ),
                );
            }
        }
        state.last_vc_frame_count = Some(header.vc_frame_count);

        if frame.fecf.is_some_and(|fecf| !fecf.is_ok()) {
            abort(&mut packets, state, "frame with FECF mismatch".to_string());
            spans.push(whole(SpanKind::Unassigned));
            continue;
        }
        if header.sync_flag == 1 {
            abort(
                &mut packets,
                state,
                "frame data field does not contain packets (Synchronization Flag 1)".to_string(),
            );
            spans.push(whole(SpanKind::Unassigned));
            continue;
        }
        if header.first_header_pointer == FHP_IDLE_DATA {
            spans.push(whole(SpanKind::Idle));
            continue;
        }

        let first_header = (header.first_header_pointer != FHP_NO_PACKET_START)
            .then_some(usize::from(header.first_header_pointer));
        if first_header.is_some_and(|fhp| fhp >= len) {
            abort(
                &mut packets,
                state,
                "First Header Pointer beyond the data field".to_string(),
            );
            spans.push(whole(SpanKind::Unassigned));
            continue;
        }

        let mut pos = 0;

        // Continuation of the packet in progress.
        if let Some(index) = state.pending {
            let limit = first_header.unwrap_or(len);
            let taken = feed(&mut packets[index], &data[..limit]);
            if taken > 0 {
                spans.push(DataSpan {
                    start: 0,
                    len: taken,
                    kind: SpanKind::Packet {
                        packet: index,
                        starts_here: false,
                    },
                });
                packets[index].frames.push(frame_index);
            }
            pos = taken;
            if octets_needed(&packets[index].bytes) == 0 {
                finish(&mut packets[index]);
                state.pending = None;
            } else if first_header.is_some() {
                abort(
                    &mut packets,
                    state,
                    "next packet starts (First Header Pointer) before this packet is complete"
                        .to_string(),
                );
            }
        }
        if state.pending.is_some() {
            // The whole data field belongs to the packet in progress.
            continue;
        }

        let Some(first_header) = first_header else {
            if pos < len {
                spans.push(DataSpan {
                    start: pos,
                    len: len - pos,
                    kind: SpanKind::Unassigned,
                });
            }
            continue;
        };
        if pos < first_header {
            spans.push(DataSpan {
                start: pos,
                len: first_header - pos,
                kind: SpanKind::Unassigned,
            });
        }
        pos = first_header;

        // Packets starting in this frame.
        let data_offset = frame.data_offset();
        while pos < len {
            let index = packets.len();
            packets.push(ExtractedPacket {
                first_frame: frame_index,
                frames: vec![frame_index],
                packet: None,
                error: None,
                bytes: Vec::new(),
                offset: data_offset + pos,
            });
            let taken = feed(&mut packets[index], &data[pos..]);
            spans.push(DataSpan {
                start: pos,
                len: taken,
                kind: SpanKind::Packet {
                    packet: index,
                    starts_here: true,
                },
            });
            pos += taken;

            if !has_valid_version(&packets[index].bytes) {
                let version = packets[index].bytes[0] >> 5;
                packets[index].error = Some(format!(
                    "unsupported Packet Version Number {version} (expected 0)"
                ));
                packets[index].bytes = Vec::new();
                if pos < len {
                    spans.push(DataSpan {
                        start: pos,
                        len: len - pos,
                        kind: SpanKind::Unassigned,
                    });
                }
                break;
            }
            if octets_needed(&packets[index].bytes) == 0 {
                finish(&mut packets[index]);
            } else {
                state.pending = Some(index);
            }
        }
    }

    // Packets still in progress at the end of the stream.
    for state in channels.values_mut() {
        abort(&mut packets, state, "stream ends".to_string());
    }

    PacketExtraction {
        packets,
        frame_spans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Fecf, TmPrimaryHeader};

    fn frame(vcid: u8, vc_count: u8, fhp: u16, data: Vec<u8>) -> TmFrame {
        TmFrame {
            offset: 0,
            header_bytes: vec![0; 6],
            header: TmPrimaryHeader {
                version: 0,
                spacecraft_id: 42,
                virtual_channel_id: vcid,
                ocf_flag: 0,
                mc_frame_count: 0,
                vc_frame_count: vc_count,
                secondary_header_flag: 0,
                sync_flag: 0,
                packet_order_flag: 0,
                segment_length_id: 3,
                first_header_pointer: fhp,
            },
            secondary_header: None,
            security_header: None,
            data,
            security_trailer: None,
            trailer_bytes: Vec::new(),
            ocf: None,
            fecf: None,
        }
    }

    /// TM packet with APID and `n` data octets.
    fn packet(apid: u16, n: usize) -> Vec<u8> {
        let mut p = vec![
            (apid >> 8) as u8,
            apid as u8,
            0xc0,
            0x00,
            ((n - 1) >> 8) as u8,
            (n - 1) as u8,
        ];
        p.extend((0..n).map(|i| i as u8));
        p
    }

    fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn packets_within_one_frame() {
        let data = concat(&[packet(1, 4), packet(2, 6)]);
        let ex = extract_packets(&[frame(1, 0, 0, data)]);
        assert_eq!(ex.packets.len(), 2);
        assert_eq!(ex.complete_count(), 2);
        assert_eq!(ex.packets[1].packet.as_ref().unwrap().header.apid, 2);
        assert_eq!(ex.frame_spans[0].len(), 2);
        assert_eq!(ex.packets_starting_in(0).count(), 2);
    }

    #[test]
    fn packet_spanning_three_frames_with_split_header() {
        // Frame 0: packet A (10 octets) + first 2 header octets of packet B (40 octets).
        let a = packet(1, 4);
        let b = packet(2, 34);
        let stream = concat(&[a.clone(), b.clone()]);
        let f0 = frame(1, 0, 0, stream[..12].to_vec());
        let f1 = frame(1, 1, FHP_NO_PACKET_START, stream[12..32].to_vec());
        let f2 = frame(1, 2, FHP_NO_PACKET_START, stream[32..].to_vec());
        let ex = extract_packets(&[f0, f1, f2]);

        assert_eq!(ex.complete_count(), 2);
        let b_extracted = &ex.packets[1];
        assert_eq!(b_extracted.first_frame, 0);
        assert_eq!(b_extracted.frames, vec![0, 1, 2]);
        assert_eq!(b_extracted.packet.as_ref().unwrap().data.len(), 34);
        assert_eq!(
            ex.frame_spans[1],
            vec![DataSpan {
                start: 0,
                len: 20,
                kind: SpanKind::Packet {
                    packet: 1,
                    starts_here: false
                }
            }]
        );
    }

    #[test]
    fn continuation_followed_by_new_packet() {
        let a = packet(1, 20); // 26 octets
        let b = packet(2, 4); // 10 octets
        let stream = concat(&[a, b]);
        let f0 = frame(1, 0, 0, stream[..16].to_vec());
        let f1 = frame(1, 1, 10, stream[16..].to_vec());
        let ex = extract_packets(&[f0, f1]);
        assert_eq!(ex.complete_count(), 2);
        assert_eq!(ex.packets_starting_in(1).count(), 1);
        assert_eq!(ex.frame_spans[1].len(), 2);
    }

    #[test]
    fn unsynchronised_start_is_unassigned() {
        // Stream starts in the middle of a packet; the next packet starts at 5.
        let mut data = vec![0xaa; 5];
        data.extend(packet(3, 2));
        let ex = extract_packets(&[frame(1, 0, 5, data)]);
        assert_eq!(ex.frame_spans[0][0].kind, SpanKind::Unassigned);
        assert_eq!(ex.frame_spans[0][0].len, 5);
        assert_eq!(ex.complete_count(), 1);
    }

    #[test]
    fn frame_count_gap_aborts_packet() {
        let a = packet(1, 30);
        let f0 = frame(1, 0, 0, a[..20].to_vec());
        let f1 = frame(1, 2, FHP_NO_PACKET_START, a[20..].to_vec());
        let ex = extract_packets(&[f0, f1]);
        assert_eq!(ex.complete_count(), 0);
        assert!(ex.packets[0].error.as_ref().unwrap().contains("gap"));
        assert_eq!(ex.frame_spans[1][0].kind, SpanKind::Unassigned);
    }

    #[test]
    fn channels_are_independent() {
        let a = packet(1, 30); // 36 octets on VC 1
        let b = packet(2, 2); // complete on VC 2
        let frames = vec![
            frame(1, 0, 0, a[..20].to_vec()),
            frame(2, 0, 0, b),
            frame(1, 1, FHP_NO_PACKET_START, a[20..].to_vec()),
        ];
        let ex = extract_packets(&frames);
        assert_eq!(ex.complete_count(), 2);
        assert_eq!(ex.packets[0].frames, vec![0, 2]);
    }

    #[test]
    fn idle_frame_and_incomplete_end() {
        let a = packet(1, 30);
        let frames = vec![
            frame(7, 0, FHP_IDLE_DATA, vec![0x55; 8]),
            frame(1, 0, 0, a[..20].to_vec()),
        ];
        let ex = extract_packets(&frames);
        assert_eq!(ex.frame_spans[0][0].kind, SpanKind::Idle);
        assert!(ex.packets[0]
            .error
            .as_ref()
            .unwrap()
            .contains("stream ends"));
    }

    #[test]
    fn crc_error_frame_interrupts() {
        let a = packet(1, 30);
        let mut bad = frame(1, 1, FHP_NO_PACKET_START, a[20..].to_vec());
        bad.fecf = Some(Fecf {
            value: 1,
            computed: 2,
        });
        let ex = extract_packets(&[frame(1, 0, 0, a[..20].to_vec()), bad]);
        assert!(ex.packets[0].error.as_ref().unwrap().contains("FECF"));
    }

    #[test]
    fn early_first_header_pointer_aborts_packet() {
        let a = packet(1, 30);
        let mut data = a[20..25].to_vec();
        data.extend(packet(2, 2));
        let frames = vec![frame(1, 0, 0, a[..20].to_vec()), frame(1, 1, 5, data)];
        let ex = extract_packets(&frames);
        assert!(ex.packets[0]
            .error
            .as_ref()
            .unwrap()
            .contains("First Header"));
        assert_eq!(ex.packets[1].packet.as_ref().unwrap().header.apid, 2);
    }

    #[test]
    fn invalid_version_stops_frame() {
        let mut data = packet(1, 2);
        data[0] |= 0x20; // version 1
        data.extend(packet(2, 2));
        let ex = extract_packets(&[frame(1, 0, 0, data)]);
        assert!(ex.packets[0].error.as_ref().unwrap().contains("Version"));
        assert_eq!(ex.packets.len(), 1);
    }
}
