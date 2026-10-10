//! Pages of the viewer and the URL hash routes leading to them.
//!
//! | Route                 | Page                                                   |
//! |-----------------------|--------------------------------------------------------|
//! | `#/` (or empty)       | overview of all packets or frames                      |
//! | `#/frame/3`           | frame overview with the detail view of frame 3 pinned  |
//! | `#/frame/3/packets`   | Space Packets starting in frame 3                      |

use ccsds_common::{PacketExtraction, Stream};

use crate::frame_view::{self, frame_href};
use crate::layout::{DetailLayout, OverviewBox};
use crate::{packet_view, tc_frame_view};

/// A page of the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Overview of the stream, optionally with a pinned detail view.
    Overview { pin: Option<usize> },
    /// Space Packets starting in the frame with the given index.
    FramePackets(usize),
}

impl Route {
    /// Parses the URL hash (`location.hash`). Unknown routes show the overview.
    pub fn parse(hash: &str) -> Route {
        let path = hash.trim_start_matches('#').trim_start_matches('/');
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        match parts.as_slice() {
            ["frame", index] => Route::Overview {
                pin: index.parse().ok(),
            },
            ["frame", index, "packets"] => match index.parse() {
                Ok(index) => Route::FramePackets(index),
                Err(_) => Route::Overview { pin: None },
            },
            _ => Route::Overview { pin: None },
        }
    }
}

/// Everything needed to render one page.
pub struct PageModel {
    /// Link above the summary line (text, URL hash), e.g. back to the frame.
    pub heading: Option<(String, String)>,
    /// Summary line.
    pub summary: String,
    /// Boxes of the overview, index = `data-index` of the box.
    pub boxes: Vec<OverviewBox>,
    /// Detail views, same index as `boxes`.
    pub details: Vec<DetailLayout>,
    /// Red frame for invalid data: (title, reason).
    pub invalid: Option<(&'static str, String)>,
    /// Box whose detail view is pinned after rendering.
    pub pin: Option<usize>,
}

/// Builds the page for a route. Routes that do not fit the stream (e.g. a
/// packet page for a packet stream) fall back to the overview.
pub fn build(stream: &Stream, route: Route) -> PageModel {
    match (stream, route) {
        (Stream::TmFrames(frames), Route::FramePackets(index)) if index < frames.frames.len() => {
            frame_packets_page(
                &frames.source,
                &frames.extraction,
                format!(
                    "TM Transfer Frame {}",
                    frames.frames[index].identification()
                ),
                index,
            )
        }
        (Stream::TcFrames(frames), Route::FramePackets(index)) if index < frames.frames.len() => {
            frame_packets_page(
                &frames.source,
                &frames.extraction,
                format!(
                    "TC Transfer Frame {}",
                    frames.frames[index].identification()
                ),
                index,
            )
        }
        (_, Route::Overview { pin }) => overview_page(stream, pin),
        (_, Route::FramePackets(_)) => overview_page(stream, None),
    }
}

/// Overview of all packets or frames.
fn overview_page(stream: &Stream, pin: Option<usize>) -> PageModel {
    let (boxes, details): (Vec<_>, Vec<_>) = match stream {
        Stream::Packets(packets) => packets
            .packets
            .iter()
            .map(|packet| (packet_view::overview(packet), packet_view::detail(packet)))
            .unzip(),
        Stream::TmFrames(frames) => (0..frames.frames.len())
            .map(|index| {
                (
                    frame_view::overview(&frames.frames[index]),
                    frame_view::detail(frames, index),
                )
            })
            .unzip(),
        Stream::TcFrames(frames) => (0..frames.frames.len())
            .map(|index| {
                (
                    tc_frame_view::overview(&frames.frames[index]),
                    tc_frame_view::detail(frames, index),
                )
            })
            .unzip(),
    };

    let invalid = stream.invalid().map(|invalid| {
        (
            stream.invalid_text(),
            format!("byte offset {}: {}", invalid.offset, invalid.reason),
        )
    });

    PageModel {
        heading: None,
        summary: overview_summary(stream),
        pin: pin.filter(|index| *index < boxes.len()),
        boxes,
        details,
        invalid,
    }
}

/// Summary line of the overview page.
fn overview_summary(stream: &Stream) -> String {
    let mut text = format!(
        "{} \u{2014} {} valid {}",
        stream.source(),
        stream.len(),
        stream.item_name()
    );
    if let Stream::TmFrames(frames) = stream {
        let config = &frames.config;
        text.push_str(&format!(", frame length {} octets", config.frame_length));
        if config.fecf_present {
            text.push_str(", FECF");
        }
        if config.asm.is_some() {
            text.push_str(", ASM");
        }
    }
    if let Stream::TcFrames(frames) = stream {
        let config = &frames.config;
        if config.segment_header {
            text.push_str(", Segment Header");
        }
        if config.fecf_present {
            text.push_str(", FECF");
        }
    }
    if stream.sdls().is_some() {
        text.push_str(", SDLS");
    }
    if stream.is_encrypted() {
        text.push_str(", data fields encrypted");
    } else if let Some(extraction) = stream.extraction() {
        text.push_str(&format!(
            ", {} Space Packet(s) extracted",
            extraction.complete_count()
        ));
    }
    if let Some(invalid) = stream.invalid() {
        text.push_str(&format!(", invalid data at byte offset {}", invalid.offset));
    }
    text.push_str(" \u{2014} click an item to pin its details");
    text
}

/// Space Packets whose header starts in the given frame. Packets continuing
/// in later frames are shown completely. The first packet that could not be
/// reassembled is shown as invalid.
fn frame_packets_page(
    source: &str,
    extraction: &PacketExtraction,
    frame_title: String,
    frame_index: usize,
) -> PageModel {
    let starting: Vec<_> = extraction.packets_starting_in(frame_index).collect();

    let complete: Vec<_> = starting
        .iter()
        .filter_map(|extracted| extracted.packet.as_ref())
        .collect();
    let invalid = starting
        .iter()
        .find_map(|extracted| extracted.error.as_ref())
        .map(|error| ("No valid Packet-Data", error.clone()));

    let continued = starting
        .iter()
        .filter(|extracted| extracted.frames.len() > 1)
        .count();
    let mut summary = format!(
        "{} \u{2014} {} Space Packet(s) starting in this frame",
        source,
        complete.len()
    );
    if continued > 0 {
        summary.push_str(&format!(
            ", {continued} of them continued in following frame(s)"
        ));
    }

    PageModel {
        heading: Some((frame_title, frame_href(frame_index))),
        summary,
        boxes: complete
            .iter()
            .map(|packet| packet_view::overview(packet))
            .collect(),
        details: complete
            .iter()
            .map(|packet| packet_view::detail(packet))
            .collect(),
        invalid,
        pin: None,
    }
}
