//! Overview: all packets of the stream side by side (wrapping into the next
//! line when the window is too narrow), each shown as
//!
//! ```text
//! +-------------------------------------------------------+
//! |                TM Space Packet APID=47                |
//! +-----------------------+-------------------------------+
//! | Packet Primary Header |       Packet Data Field       |
//! +-----------------------+-------------------------------+
//! |   08 2f c0 01 00 03   |  de ad be ef                  |
//! +-----------------------+-------------------------------+
//! ```

use ccsds_common::{format_hex_bytes, PacketStream, SpacePacket};
use wasm_bindgen::JsValue;
use web_sys::{Document, Element};

use crate::dom::{create, create_text};

/// Text shown in the red frame for the first invalid packet.
pub const INVALID_TEXT: &str = "No valid Packet-Data";

/// Renders all valid packets and (if present) the first invalid packet.
pub fn render(
    document: &Document,
    container: &Element,
    stream: &PacketStream,
) -> Result<(), JsValue> {
    container.set_inner_html("");

    for (index, packet) in stream.packets.iter().enumerate() {
        container.append_child(&packet_box(document, index, packet)?.into())?;
    }

    if let Some(invalid) = &stream.invalid {
        let frame = create(document, "div", "invalid")?;
        frame.append_child(&create_text(
            document,
            "div",
            "invalid-title",
            INVALID_TEXT,
        )?.into())?;
        frame.append_child(&create_text(
            document,
            "div",
            "invalid-reason",
            &format!("byte offset {}: {}", invalid.offset, invalid.reason),
        )?.into())?;
        container.append_child(&frame)?;
    }

    Ok(())
}

/// Builds the framed overview box of one packet.
fn packet_box(document: &Document, index: usize, packet: &SpacePacket) -> Result<Element, JsValue> {
    let frame = create(document, "div", "packet")?;
    frame.set_attribute("data-index", &index.to_string())?;

    frame.append_child(&create_text(
        document,
        "div",
        "cell packet-title",
        &packet.title(),
    )?.into())?;
    frame.append_child(&create_text(
        document,
        "div",
        "cell section-title",
        "Packet Primary Header",
    )?.into())?;
    frame.append_child(&create_text(
        document,
        "div",
        "cell section-title",
        "Packet Data Field",
    )?.into())?;
    frame.append_child(&create_text(
        document,
        "div",
        "cell hex header-hex",
        &format_hex_bytes(&packet.header_bytes),
    )?.into())?;
    frame.append_child(&create_text(
        document,
        "div",
        "cell hex data-hex",
        &format_hex_bytes(&packet.data),
    )?.into())?;

    Ok(frame)
}
