//! Views of a CCSDS Space Packet.

use ccsds_common::{format_hex_value, PrimaryHeader, SpacePacket};

use crate::layout::{
    DetailLayout, DetailSection, Field, Group, Item, OverviewBox, OverviewSection, SectionContent,
    Value,
};

/// Overview: Packet Primary Header and Packet Data Field.
pub fn overview(packet: &SpacePacket) -> OverviewBox {
    OverviewBox {
        title: packet.title(),
        sections: vec![
            OverviewSection::fixed("Packet Primary Header", &packet.header_bytes),
            OverviewSection::wrapping("Packet Data Field", &packet.data),
        ],
    }
}

/// Detail view with all fields of the Packet Primary Header.
pub fn detail(packet: &SpacePacket) -> DetailLayout {
    let h = &packet.header;

    let header = vec![
        Item::Field(Field::number(
            "Packet Version Number",
            h.version.into(),
            PrimaryHeader::VERSION_BITS,
        )),
        Item::Group(Group {
            title: "Packet Identification",
            value: format_hex_value(
                h.packet_identification().into(),
                PrimaryHeader::PACKET_IDENTIFICATION_BITS,
            ),
            fields: vec![
                Field::number(
                    "Packet Type",
                    h.packet_type.bit().into(),
                    PrimaryHeader::PACKET_TYPE_BITS,
                ),
                Field::number(
                    "Secondary Header Flag",
                    h.secondary_header_flag.into(),
                    PrimaryHeader::SECONDARY_HEADER_FLAG_BITS,
                ),
                Field::number(
                    "Application Process Identifier",
                    h.apid.into(),
                    PrimaryHeader::APID_BITS,
                ),
            ],
        }),
        Item::Group(Group {
            title: "Packet Sequence Control",
            value: format_hex_value(
                h.packet_sequence_control().into(),
                PrimaryHeader::PACKET_SEQUENCE_CONTROL_BITS,
            ),
            fields: vec![
                Field::number(
                    "Sequence Flags",
                    h.sequence_flags.into(),
                    PrimaryHeader::SEQUENCE_FLAGS_BITS,
                ),
                Field::number(
                    "Packet Sequence Count or Packet Name",
                    h.sequence_count.into(),
                    PrimaryHeader::SEQUENCE_COUNT_BITS,
                ),
            ],
        }),
        Item::Field(Field::number(
            "Packet Data Length",
            h.data_length.into(),
            PrimaryHeader::DATA_LENGTH_BITS,
        )),
    ];

    DetailLayout {
        title: packet.title(),
        sections: vec![
            DetailSection {
                title: "Packet Primary Header",
                content: SectionContent::Items(header),
            },
            DetailSection {
                title: "Packet Data Field",
                content: SectionContent::Value(Value::Bytes(packet.data.clone())),
            },
        ],
    }
}
