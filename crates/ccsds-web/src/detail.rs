//! Detail view of a single packet, laid out as a CSS grid with 8 columns
//! (7 header fields + Packet Data Field) and 6 rows:
//!
//! ```text
//! row 1 |                     TM Space Packet APID=47                          |
//! row 2 |                Packet Primary Header                 | Packet Data   |
//! row 3 | Version | Packet Identification  | Pkt.Seq.Control | Data   | Field |
//! row 4 |  Number |        0x082f          |     0xc001      | Length |       |
//! row 5 |         | Type | Sec.Hdr | APID  | Flags | Count   |        |       |
//! row 6 |    0    |  0   |    1    |  47   |   3   |   1     |   3    | de ad |
//! ```
//!
//! Fields without a parent group (Packet Version Number, Packet Data Length)
//! extend their name cell over the group rows 3 and 4; the Packet Data Field
//! title extends from row 2 down to row 5.

use ccsds_common::{format_hex_bytes, format_hex_value, FieldValue, PrimaryHeader, SpacePacket};
use wasm_bindgen::JsValue;
use web_sys::{Document, Element};

use crate::dom::{create, create_text, place};

/// Grid column (1-based) of the Packet Data Field.
const DATA_COLUMN: u32 = 8;

/// Builds the detail grid of one packet.
pub fn build(document: &Document, packet: &SpacePacket) -> Result<Element, JsValue> {
    let header = &packet.header;
    let grid = create(document, "div", "detail")?;

    // Row 1: packet title over the full width.
    add_text(
        document,
        &grid,
        "cell packet-title",
        &packet.title(),
        "1 / -1",
        "1",
    )?;

    // Row 2: Packet Primary Header and Packet Data Field.
    add_text(
        document,
        &grid,
        "cell section-title",
        "Packet Primary Header",
        "1 / 8",
        "2",
    )?;
    add_text(
        document,
        &grid,
        "cell section-title",
        "Packet Data Field",
        &DATA_COLUMN.to_string(),
        "2 / 6",
    )?;

    // Rows 3 and 4: group titles and group values (hex only).
    add_text(
        document,
        &grid,
        "cell group-title",
        "Packet Identification",
        "2 / 5",
        "3",
    )?;
    add_text(
        document,
        &grid,
        "cell group-title",
        "Packet Sequence Control",
        "5 / 7",
        "3",
    )?;
    add_text(
        document,
        &grid,
        "cell group-value",
        &format_hex_value(
            header.packet_identification().into(),
            PrimaryHeader::PACKET_IDENTIFICATION_BITS,
        ),
        "2 / 5",
        "4",
    )?;
    add_text(
        document,
        &grid,
        "cell group-value",
        &format_hex_value(
            header.packet_sequence_control().into(),
            PrimaryHeader::PACKET_SEQUENCE_CONTROL_BITS,
        ),
        "5 / 7",
        "4",
    )?;

    // Rows 5 and 6: field names and field values. Fields without a parent
    // group start their name cell in row 3.
    let fields: [(&str, u32, u32, bool); 7] = [
        (
            "Packet Version Number",
            header.version.into(),
            PrimaryHeader::VERSION_BITS,
            false,
        ),
        (
            "Packet Type",
            header.packet_type.bit().into(),
            PrimaryHeader::PACKET_TYPE_BITS,
            true,
        ),
        (
            "Secondary Header Flag",
            header.secondary_header_flag.into(),
            PrimaryHeader::SECONDARY_HEADER_FLAG_BITS,
            true,
        ),
        (
            "Application Process Identifier",
            header.apid.into(),
            PrimaryHeader::APID_BITS,
            true,
        ),
        (
            "Sequence Flags",
            header.sequence_flags.into(),
            PrimaryHeader::SEQUENCE_FLAGS_BITS,
            true,
        ),
        (
            "Packet Sequence Count or Packet Name",
            header.sequence_count.into(),
            PrimaryHeader::SEQUENCE_COUNT_BITS,
            true,
        ),
        (
            "Packet Data Length",
            header.data_length.into(),
            PrimaryHeader::DATA_LENGTH_BITS,
            false,
        ),
    ];

    for (index, (name, value, bits, grouped)) in fields.iter().enumerate() {
        let column = (index + 1).to_string();
        let name_rows = if *grouped { "5" } else { "3 / 6" };
        add_text(document, &grid, "cell field-name", name, &column, name_rows)?;
        grid.append_child(&value_cell(
            document,
            &FieldValue::new(*value, *bits),
            &column,
        )?.into())?;
    }

    // Row 6, last column: content of the Packet Data Field.
    add_text(
        document,
        &grid,
        "cell hex data-hex",
        &format_hex_bytes(&packet.data),
        &DATA_COLUMN.to_string(),
        "6",
    )?;

    Ok(grid)
}

/// Appends a text cell at the given grid position.
fn add_text(
    document: &Document,
    grid: &Element,
    class: &str,
    text: &str,
    column: &str,
    row: &str,
) -> Result<(), JsValue> {
    let cell = create_text(document, "div", class, text)?;
    place(&cell, column, row)?;
    grid.append_child(&cell)?;
    Ok(())
}

/// Builds the value cell of a header field: decimal value, plus the hex
/// value below it for fields that can hold values greater than 9.
fn value_cell(document: &Document, value: &FieldValue, column: &str) -> Result<Element, JsValue> {
    let cell = create(document, "div", "cell field-value")?;
    place(&cell, column, "6")?;
    cell.append_child(&create_text(document, "span", "dec", &value.decimal)?.into())?;
    if let Some(hex) = &value.hex {
        cell.append_child(&create_text(document, "span", "hexval", hex)?.into())?;
    }
    Ok(cell)
}
