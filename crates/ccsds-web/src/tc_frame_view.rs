//! Views of a CCSDS TC Transfer Frame.

use ccsds_common::{TcFrame, TcFrameStream, TcPrimaryHeader, TcSegmentHeader};

use crate::frame_view::{data_field_value, fecf_value};
use crate::layout::{
    ByteRun, DetailLayout, DetailSection, Field, Item, OverviewBox, OverviewSection,
    SectionContent, Value,
};

const PRIMARY_HEADER: &str = "Transfer Frame Primary Header";
const SEGMENT_HEADER: &str = "Segment Header";
const SECURITY_HEADER: &str = "Security Header";
const DATA_FIELD: &str = "Transfer Frame Data Field";
const SECURITY_TRAILER: &str = "Security Trailer";
const FECF: &str = "Frame Error Control Field";

/// Overview: the top level parts of the frame. Segment Header, Security
/// Header, Security Trailer and Frame Error Control Field only appear if
/// they are present in the frame.
pub fn overview(frame: &TcFrame) -> OverviewBox {
    let mut sections = vec![OverviewSection::fixed(PRIMARY_HEADER, &frame.header_bytes)];
    if let Some(segment) = &frame.segment_header {
        sections.push(OverviewSection::fixed(SEGMENT_HEADER, &[segment.octet()]));
    }
    if let Some(security) = &frame.security_header {
        sections.push(OverviewSection::wrapping(SECURITY_HEADER, security));
    }
    sections.push(OverviewSection::wrapping(DATA_FIELD, &frame.data));
    if let Some(security) = &frame.security_trailer {
        sections.push(OverviewSection::wrapping(SECURITY_TRAILER, security));
    }
    if let Some(fecf) = &frame.fecf {
        sections.push(OverviewSection::fixed(FECF, &fecf.value.to_be_bytes()));
    }

    OverviewBox {
        title: frame.title(),
        sections,
    }
}

/// Detail view with all fields of the frame with the given index.
pub fn detail(stream: &TcFrameStream, frame_index: usize) -> DetailLayout {
    let frame = &stream.frames[frame_index];
    let mut sections = vec![DetailSection {
        title: PRIMARY_HEADER,
        content: SectionContent::Items(primary_header_items(&frame.header)),
    }];

    if let Some(segment) = &frame.segment_header {
        sections.push(DetailSection {
            title: SEGMENT_HEADER,
            content: SectionContent::Items(segment_header_items(segment)),
        });
    }

    if let Some(security) = &frame.security_header {
        sections.push(DetailSection {
            title: SECURITY_HEADER,
            content: SectionContent::Value(Value::Bytes(security.clone())),
        });
    }

    let data = match frame.control_command() {
        Some(name) => Value::Runs(vec![ByteRun {
            bytes: frame.data.clone(),
            href: None,
            class: "control",
            tooltip: format!("control command: {name}"),
        }]),
        None => data_field_value(&frame.data, &stream.extraction, frame_index, |first| {
            stream.frames[first].identification()
        }),
    };
    sections.push(DetailSection {
        title: DATA_FIELD,
        content: SectionContent::Value(data),
    });

    if let Some(security) = &frame.security_trailer {
        sections.push(DetailSection {
            title: SECURITY_TRAILER,
            content: SectionContent::Value(Value::Bytes(security.clone())),
        });
    }

    if let Some(fecf) = frame.fecf {
        sections.push(DetailSection {
            title: FECF,
            content: SectionContent::Value(fecf_value(fecf)),
        });
    }

    DetailLayout {
        title: frame.title(),
        sections,
    }
}

fn primary_header_items(h: &TcPrimaryHeader) -> Vec<Item> {
    let bypass_note = if h.bypass_flag == 0 {
        "Type-A"
    } else {
        "Type-B"
    };
    let control_note = if h.is_control() { "Type-C" } else { "Type-D" };

    vec![
        Item::Field(Field::number(
            "Transfer Frame Version Number",
            h.version.into(),
            TcPrimaryHeader::VERSION_BITS,
        )),
        Item::Field(Field::new(
            "Bypass Flag",
            Value::number(h.bypass_flag.into(), TcPrimaryHeader::BYPASS_FLAG_BITS)
                .with_note(bypass_note, false),
        )),
        Item::Field(Field::new(
            "Control Command Flag",
            Value::number(
                h.control_command_flag.into(),
                TcPrimaryHeader::CONTROL_COMMAND_FLAG_BITS,
            )
            .with_note(control_note, false),
        )),
        Item::Field(Field::number(
            "Reserved Spare",
            h.spare.into(),
            TcPrimaryHeader::SPARE_BITS,
        )),
        Item::Field(Field::number(
            "Spacecraft Identifier",
            h.spacecraft_id.into(),
            TcPrimaryHeader::SPACECRAFT_ID_BITS,
        )),
        Item::Field(Field::number(
            "Virtual Channel Identifier",
            h.virtual_channel_id.into(),
            TcPrimaryHeader::VIRTUAL_CHANNEL_ID_BITS,
        )),
        Item::Field(Field::new(
            "Frame Length",
            Value::number(h.frame_length.into(), TcPrimaryHeader::FRAME_LENGTH_BITS)
                .with_note(format!("{} octets", h.total_length()), false),
        )),
        Item::Field(Field::number(
            "Frame Sequence Number",
            h.frame_sequence_number.into(),
            TcPrimaryHeader::FRAME_SEQUENCE_NUMBER_BITS,
        )),
    ]
}

fn segment_header_items(segment: &TcSegmentHeader) -> Vec<Item> {
    vec![
        Item::Field(Field::new(
            "Sequence Flags",
            Value::number(
                segment.sequence_flags.into(),
                TcSegmentHeader::SEQUENCE_FLAGS_BITS,
            )
            .with_note(segment.sequence_flags_note(), false),
        )),
        Item::Field(Field::number(
            "Multiplexer Access Point Identifier",
            segment.map_id.into(),
            TcSegmentHeader::MAP_ID_BITS,
        )),
    ]
}
