//! Generic description and rendering of the framed views.
//!
//! Space Packets and TM Transfer Frames are both displayed with the same
//! frame structure, so the views are described by a small data model
//! ([`OverviewBox`], [`DetailLayout`]) which is filled by `packet_view` and
//! `frame_view` and rendered here.
//!
//! Detail view grid (one column per field):
//!
//! ```text
//! row 1 |                          title                                       |
//! row 2 |          section title                  |  section title   | section |
//! row 3 | ungrouped  | group title  | ungrouped   | ungrouped field  | with a  |
//! row 4 | field name | group value  | field name  | name             | single  |
//! row 5 |            | name | name  |             |                  | value   |
//! row 6 | value      | val  | val   | value       | value            | value   |
//! ```

use ccsds_common::{format_hex_bytes, FieldValue};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Document, Element, HtmlElement};

use crate::dom::{create, create_text, place};

// ---------------------------------------------------------------------------
// Overview model
// ---------------------------------------------------------------------------

/// Overview of one item: title plus a row of framed sections with hex bytes.
pub struct OverviewBox {
    pub title: String,
    pub sections: Vec<OverviewSection>,
}

/// One framed section of the overview.
pub struct OverviewSection {
    pub title: &'static str,
    pub bytes: Vec<u8>,
    /// Allow wrapping into several lines (16 octets per line).
    pub wrap: bool,
}

impl OverviewSection {
    /// Short section, always shown on one line.
    pub fn fixed(title: &'static str, bytes: &[u8]) -> Self {
        OverviewSection {
            title,
            bytes: bytes.to_vec(),
            wrap: false,
        }
    }

    /// Section of variable length, wrapped after 16 octets.
    pub fn wrapping(title: &'static str, bytes: &[u8]) -> Self {
        OverviewSection {
            title,
            bytes: bytes.to_vec(),
            wrap: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Detail model
// ---------------------------------------------------------------------------

/// Complete detail view of one item.
pub struct DetailLayout {
    pub title: String,
    pub sections: Vec<DetailSection>,
}

/// A section such as "Packet Primary Header" or "Transfer Frame Trailer".
pub struct DetailSection {
    pub title: &'static str,
    pub content: SectionContent,
}

/// Content of a section.
pub enum SectionContent {
    /// The section has no sub fields; the value is shown directly below the
    /// (vertically extended) section title, e.g. "Packet Data Field".
    Value(Value),
    /// The section consists of fields, optionally grouped.
    Items(Vec<Item>),
}

/// Element of a section.
pub enum Item {
    /// Field without parent group: its name cell extends over the group rows.
    Field(Field),
    /// Group of fields with a common title and a hex value.
    Group(Group),
}

/// A group such as "Packet Identification".
pub struct Group {
    pub title: &'static str,
    /// Value of the whole group, shown in hex with `0x` prefix.
    pub value: String,
    pub fields: Vec<Field>,
}

/// A single field.
pub struct Field {
    pub name: &'static str,
    pub value: Value,
}

/// The value of a field.
pub enum Value {
    /// Number: decimal, plus hex if the field can be greater than 9.
    Number {
        value: FieldValue,
        note: Option<Note>,
    },
    /// Octet string shown as hex bytes.
    Bytes(Vec<u8>),
    /// Octet string divided into runs, each optionally shown as a link
    /// (e.g. the packets contained in a frame data field).
    Runs(Vec<ByteRun>),
}

/// A part of an octet string with its own style and optional link.
pub struct ByteRun {
    pub bytes: Vec<u8>,
    /// Link target (URL hash), if the run is clickable.
    pub href: Option<String>,
    /// Additional CSS classes, e.g. `"pkt-a start"`.
    pub class: &'static str,
    /// Tooltip text.
    pub tooltip: String,
}

/// Additional remark below a value, e.g. "CRC ok".
pub struct Note {
    pub text: String,
    /// Shown as error (red).
    pub bad: bool,
}

impl Value {
    /// Numeric value of a field with the given bit width.
    pub fn number(value: u32, bits: u32) -> Self {
        Value::Number {
            value: FieldValue::new(value, bits),
            note: None,
        }
    }

    /// Adds a note to a numeric value.
    pub fn with_note(self, text: impl Into<String>, bad: bool) -> Self {
        match self {
            Value::Number { value, .. } => Value::Number {
                value,
                note: Some(Note {
                    text: text.into(),
                    bad,
                }),
            },
            other => other,
        }
    }
}

impl Field {
    /// Numeric field.
    pub fn number(name: &'static str, value: u32, bits: u32) -> Self {
        Field {
            name,
            value: Value::number(value, bits),
        }
    }

    /// Field with an arbitrary value.
    pub fn new(name: &'static str, value: Value) -> Self {
        Field { name, value }
    }
}

impl SectionContent {
    /// Number of grid columns needed by this content.
    fn columns(&self) -> usize {
        match self {
            SectionContent::Value(_) => 1,
            SectionContent::Items(items) => items
                .iter()
                .map(|item| match item {
                    Item::Field(_) => 1,
                    Item::Group(group) => group.fields.len(),
                })
                .sum(),
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Renders an overview box. `index` identifies the item for the hover logic.
pub fn render_overview_box(
    document: &Document,
    index: usize,
    model: &OverviewBox,
) -> Result<Element, JsValue> {
    let frame = create(document, "div", "packet")?;
    frame.set_attribute("data-index", &index.to_string())?;
    frame.unchecked_ref::<HtmlElement>().style().set_property(
        "grid-template-columns",
        &format!("repeat({}, auto)", model.sections.len()),
    )?;

    frame.append_child(&create_text(document, "div", "cell packet-title", &model.title)?.into())?;
    for section in &model.sections {
        frame.append_child(
            &create_text(document, "div", "cell section-title", section.title)?.into(),
        )?;
    }
    for section in &model.sections {
        let class = if section.wrap {
            "cell hex data-hex"
        } else {
            "cell hex header-hex"
        };
        frame.append_child(
            &create_text(document, "div", class, &format_hex_bytes(&section.bytes))?.into(),
        )?;
    }
    Ok(frame)
}

/// Renders the red frame for the first invalid item.
pub fn render_invalid(document: &Document, text: &str, reason: &str) -> Result<Element, JsValue> {
    let frame = create(document, "div", "invalid")?;
    frame.append_child(&create_text(document, "div", "invalid-title", text)?.into())?;
    frame.append_child(&create_text(document, "div", "invalid-reason", reason)?.into())?;
    Ok(frame)
}

/// Renders the detail grid.
pub fn render_detail(document: &Document, layout: &DetailLayout) -> Result<Element, JsValue> {
    let grid = create(document, "div", "detail")?;
    let total_columns: usize = layout
        .sections
        .iter()
        .map(|section| section.content.columns())
        .sum();
    grid.unchecked_ref::<HtmlElement>().style().set_property(
        "grid-template-columns",
        &format!("repeat({total_columns}, minmax(4.5rem, max-content))"),
    )?;

    // Row 1: title over the full width.
    add_text(
        document,
        &grid,
        "cell packet-title",
        &layout.title,
        "1 / -1",
        "1",
    )?;

    let mut column = 1usize;
    for section in &layout.sections {
        let width = section.content.columns();
        match &section.content {
            SectionContent::Value(value) => {
                // Title extends from row 2 down to row 5, value in row 6.
                add_text(
                    document,
                    &grid,
                    "cell section-title",
                    section.title,
                    &column.to_string(),
                    "2 / 6",
                )?;
                add_value(document, &grid, value, column)?;
                column += 1;
            }
            SectionContent::Items(items) => {
                add_text(
                    document,
                    &grid,
                    "cell section-title",
                    section.title,
                    &span(column, width),
                    "2",
                )?;
                for item in items {
                    match item {
                        Item::Field(field) => {
                            // No parent group: name covers the group rows too.
                            add_name(document, &grid, field.name, &column.to_string(), "3 / 6")?;
                            add_value(document, &grid, &field.value, column)?;
                            column += 1;
                        }
                        Item::Group(group) => {
                            let group_span = span(column, group.fields.len());
                            add_text(
                                document,
                                &grid,
                                "cell group-title",
                                group.title,
                                &group_span,
                                "3",
                            )?;
                            add_text(
                                document,
                                &grid,
                                "cell group-value",
                                &group.value,
                                &group_span,
                                "4",
                            )?;
                            for field in &group.fields {
                                add_name(document, &grid, field.name, &column.to_string(), "5")?;
                                add_value(document, &grid, &field.value, column)?;
                                column += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(grid)
}

/// CSS grid column span starting at `start` covering `width` columns.
fn span(start: usize, width: usize) -> String {
    format!("{} / {}", start, start + width)
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

/// Appends a field name cell. The text sits in an inner element with a
/// limited width, so long names wrap while the cell still fills the whole
/// grid column (no gaps when a group title is wider than its fields).
fn add_name(
    document: &Document,
    grid: &Element,
    name: &str,
    column: &str,
    row: &str,
) -> Result<(), JsValue> {
    let cell = create(document, "div", "cell field-name")?;
    cell.append_child(&create_text(document, "span", "label", name)?.into())?;
    place(&cell, column, row)?;
    grid.append_child(&cell)?;
    Ok(())
}

/// Appends the value cell (row 6) of a field.
fn add_value(
    document: &Document,
    grid: &Element,
    value: &Value,
    column: usize,
) -> Result<(), JsValue> {
    let cell = match value {
        Value::Bytes(bytes) => create_text(
            document,
            "div",
            "cell hex data-hex",
            &format_hex_bytes(bytes),
        )?,
        Value::Runs(runs) => {
            let cell = create(document, "div", "cell hex data-hex runs")?;
            // Inner block element: the cell itself is a flex container.
            let text = create(document, "div", "runs-text")?;
            for (index, run) in runs.iter().enumerate() {
                if index > 0 {
                    text.append_child(&document.create_text_node(" "))?;
                }
                let tag = if run.href.is_some() { "a" } else { "span" };
                let element = create_text(
                    document,
                    tag,
                    &format!("run {}", run.class),
                    &format_hex_bytes(&run.bytes),
                )?;
                if let Some(href) = &run.href {
                    element.set_attribute("href", href)?;
                }
                if !run.tooltip.is_empty() {
                    element.set_attribute("title", &run.tooltip)?;
                }
                text.append_child(&element)?;
            }
            cell.append_child(&text)?;
            cell
        }
        Value::Number { value, note } => {
            let cell = create(document, "div", "cell field-value")?;
            cell.append_child(&create_text(document, "span", "dec", &value.decimal)?.into())?;
            if let Some(hex) = &value.hex {
                cell.append_child(&create_text(document, "span", "hexval", hex)?.into())?;
            }
            if let Some(note) = note {
                let class = if note.bad { "note bad" } else { "note" };
                cell.append_child(&create_text(document, "span", class, &note.text)?.into())?;
            }
            cell
        }
    };
    place(&cell, &column.to_string(), "6")?;
    grid.append_child(&cell)?;
    Ok(())
}
