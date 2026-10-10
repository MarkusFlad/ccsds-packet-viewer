//! Views of a CCSDS TM Transfer Frame.

use ccsds_common::{
    format_hex_value, FrameStream, SpanKind, TmFrame, TmPrimaryHeader, TmSecondaryHeader,
};

use crate::layout::{
    ByteRun, DetailLayout, DetailSection, Field, Group, Item, OverviewBox, OverviewSection,
    SectionContent, Value,
};

const PRIMARY_HEADER: &str = "Transfer Frame Primary Header";
const SECONDARY_HEADER: &str = "Transfer Frame Secondary Header";
const SECURITY_HEADER: &str = "Security Header";
const DATA_FIELD: &str = "Transfer Frame Data Field";
const SECURITY_TRAILER: &str = "Security Trailer";
const TRAILER: &str = "Transfer Frame Trailer";

/// Overview: the top level parts of the frame. Secondary Header, Security
/// Header, Security Trailer and Trailer only appear if they are present in
/// the frame.
pub fn overview(frame: &TmFrame) -> OverviewBox {
    let mut sections = vec![OverviewSection::fixed(PRIMARY_HEADER, &frame.header_bytes)];
    if let Some(secondary) = &frame.secondary_header {
        sections.push(OverviewSection::wrapping(
            SECONDARY_HEADER,
            &secondary.bytes,
        ));
    }
    if let Some(security) = &frame.security_header {
        sections.push(OverviewSection::wrapping(SECURITY_HEADER, security));
    }
    sections.push(OverviewSection::wrapping(DATA_FIELD, &frame.data));
    if let Some(security) = &frame.security_trailer {
        sections.push(OverviewSection::wrapping(SECURITY_TRAILER, security));
    }
    if frame.has_trailer() {
        sections.push(OverviewSection::fixed(TRAILER, &frame.trailer_bytes));
    }

    OverviewBox {
        title: frame.title(),
        sections,
    }
}

/// URL hash of the page listing the Space Packets that start in a frame.
pub fn packets_href(frame_index: usize) -> String {
    format!("#/frame/{frame_index}/packets")
}

/// URL hash of the frame overview with the detail view of a frame pinned.
pub fn frame_href(frame_index: usize) -> String {
    format!("#/frame/{frame_index}")
}

/// Detail view with all fields of the frame with the given index.
pub fn detail(stream: &FrameStream, frame_index: usize) -> DetailLayout {
    let frame = &stream.frames[frame_index];
    let mut sections = vec![DetailSection {
        title: PRIMARY_HEADER,
        content: SectionContent::Items(primary_header_items(&frame.header)),
    }];

    if let Some(secondary) = &frame.secondary_header {
        sections.push(DetailSection {
            title: SECONDARY_HEADER,
            content: SectionContent::Items(secondary_header_items(secondary)),
        });
    }

    if let Some(security) = &frame.security_header {
        sections.push(DetailSection {
            title: SECURITY_HEADER,
            content: SectionContent::Value(Value::Bytes(security.clone())),
        });
    }

    sections.push(DetailSection {
        title: DATA_FIELD,
        content: SectionContent::Value(data_field_value(stream, frame_index)),
    });

    if let Some(security) = &frame.security_trailer {
        sections.push(DetailSection {
            title: SECURITY_TRAILER,
            content: SectionContent::Value(Value::Bytes(security.clone())),
        });
    }

    if frame.has_trailer() {
        sections.push(DetailSection {
            title: TRAILER,
            content: SectionContent::Items(trailer_items(frame)),
        });
    }

    DetailLayout {
        title: frame.title(),
        sections,
    }
}

/// The data field divided into the packets it contains. Packet parts link
/// to the packet page of the frame in which the packet starts.
fn data_field_value(stream: &FrameStream, frame_index: usize) -> Value {
    let frame = &stream.frames[frame_index];
    let extraction = &stream.extraction;
    let Some(spans) = extraction.frame_spans.get(frame_index) else {
        return Value::Bytes(frame.data.clone());
    };

    let runs = spans
        .iter()
        .map(|span| {
            let bytes = frame.data[span.start..span.start + span.len].to_vec();
            match span.kind {
                SpanKind::Packet {
                    packet,
                    starts_here,
                } => {
                    let extracted = &extraction.packets[packet];
                    let first = &stream.frames[extracted.first_frame];
                    let mut tooltip = if starts_here {
                        format!("{}: starts here", extracted.title())
                    } else {
                        format!(
                            "{}: continued from frame {}",
                            extracted.title(),
                            first.identification()
                        )
                    };
                    if let Some(error) = &extracted.error {
                        tooltip.push_str(&format!(" ({error})"));
                    }
                    let class = match (packet % 2 == 0, starts_here) {
                        (true, true) => "pkt-a start",
                        (true, false) => "pkt-a",
                        (false, true) => "pkt-b start",
                        (false, false) => "pkt-b",
                    };
                    ByteRun {
                        bytes,
                        href: Some(packets_href(extracted.first_frame)),
                        class,
                        tooltip,
                    }
                }
                SpanKind::Idle => ByteRun {
                    bytes,
                    href: None,
                    class: "idle",
                    tooltip: "idle data".to_string(),
                },
                SpanKind::Unassigned => ByteRun {
                    bytes,
                    href: None,
                    class: "unassigned",
                    tooltip: "not assigned to a packet (start of the packet not received)"
                        .to_string(),
                },
            }
        })
        .collect();
    Value::Runs(runs)
}

fn primary_header_items(h: &TmPrimaryHeader) -> Vec<Item> {
    let first_header_pointer = {
        let value = Value::number(
            h.first_header_pointer.into(),
            TmPrimaryHeader::FIRST_HEADER_POINTER_BITS,
        );
        match h.first_header_pointer_note() {
            Some(note) => value.with_note(note, false),
            None => value,
        }
    };

    vec![
        Item::Group(Group {
            title: "Master Channel Identifier",
            value: format_hex_value(
                h.master_channel_id().into(),
                TmPrimaryHeader::MASTER_CHANNEL_ID_BITS,
            ),
            fields: vec![
                Field::number(
                    "Transfer Frame Version Number",
                    h.version.into(),
                    TmPrimaryHeader::VERSION_BITS,
                ),
                Field::number(
                    "Spacecraft Identifier",
                    h.spacecraft_id.into(),
                    TmPrimaryHeader::SPACECRAFT_ID_BITS,
                ),
            ],
        }),
        Item::Field(Field::number(
            "Virtual Channel Identifier",
            h.virtual_channel_id.into(),
            TmPrimaryHeader::VIRTUAL_CHANNEL_ID_BITS,
        )),
        Item::Field(Field::number(
            "Operational Control Field Flag",
            h.ocf_flag.into(),
            TmPrimaryHeader::OCF_FLAG_BITS,
        )),
        Item::Field(Field::number(
            "Master Channel Frame Count",
            h.mc_frame_count.into(),
            TmPrimaryHeader::MC_FRAME_COUNT_BITS,
        )),
        Item::Field(Field::number(
            "Virtual Channel Frame Count",
            h.vc_frame_count.into(),
            TmPrimaryHeader::VC_FRAME_COUNT_BITS,
        )),
        Item::Group(Group {
            title: "Transfer Frame Data Field Status",
            value: format_hex_value(
                h.data_field_status().into(),
                TmPrimaryHeader::DATA_FIELD_STATUS_BITS,
            ),
            fields: vec![
                Field::number(
                    "Transfer Frame Secondary Header Flag",
                    h.secondary_header_flag.into(),
                    TmPrimaryHeader::SECONDARY_HEADER_FLAG_BITS,
                ),
                Field::number(
                    "Synchronization Flag",
                    h.sync_flag.into(),
                    TmPrimaryHeader::SYNC_FLAG_BITS,
                ),
                Field::number(
                    "Packet Order Flag",
                    h.packet_order_flag.into(),
                    TmPrimaryHeader::PACKET_ORDER_FLAG_BITS,
                ),
                Field::number(
                    "Segment Length Identifier",
                    h.segment_length_id.into(),
                    TmPrimaryHeader::SEGMENT_LENGTH_ID_BITS,
                ),
                Field::new("First Header Pointer", first_header_pointer),
            ],
        }),
    ]
}

fn secondary_header_items(secondary: &TmSecondaryHeader) -> Vec<Item> {
    vec![
        Item::Group(Group {
            title: "Transfer Frame Secondary Header Identification",
            value: format_hex_value(
                secondary.identification().into(),
                TmSecondaryHeader::IDENTIFICATION_BITS,
            ),
            fields: vec![
                Field::number(
                    "Transfer Frame Secondary Header Version Number",
                    secondary.version.into(),
                    TmSecondaryHeader::VERSION_BITS,
                ),
                Field::number(
                    "Transfer Frame Secondary Header Length",
                    secondary.length.into(),
                    TmSecondaryHeader::LENGTH_BITS,
                ),
            ],
        }),
        Item::Field(Field::new(
            "Transfer Frame Secondary Header Data Field",
            Value::Bytes(secondary.data.clone()),
        )),
    ]
}

fn trailer_items(frame: &TmFrame) -> Vec<Item> {
    let mut items = Vec::new();
    if let Some(ocf) = frame.ocf {
        items.push(Item::Field(Field::number(
            "Operational Control Field",
            ocf,
            TmFrame::OCF_BITS,
        )));
    }
    if let Some(fecf) = frame.fecf {
        let value = Value::number(fecf.value.into(), ccsds_common::Fecf::BITS);
        let value = if fecf.is_ok() {
            value.with_note("CRC ok", false)
        } else {
            value.with_note(
                format!(
                    "CRC error, computed {}",
                    format_hex_value(fecf.computed.into(), ccsds_common::Fecf::BITS)
                ),
                true,
            )
        };
        items.push(Item::Field(Field::new("Frame Error Control Field", value)));
    }
    items
}
