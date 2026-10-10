//! Small helpers for building DOM elements.

use wasm_bindgen::{JsCast, JsValue};
use web_sys::{Document, Element, HtmlElement};

/// Creates an element with the given CSS class(es).
pub fn create(document: &Document, tag: &str, class: &str) -> Result<Element, JsValue> {
    let element = document.create_element(tag)?;
    if !class.is_empty() {
        element.set_class_name(class);
    }
    Ok(element)
}

/// Creates an element with CSS class(es) and text content.
pub fn create_text(
    document: &Document,
    tag: &str,
    class: &str,
    text: &str,
) -> Result<Element, JsValue> {
    let element = create(document, tag, class)?;
    element.set_text_content(Some(text));
    Ok(element)
}

/// Positions an element inside a CSS grid, e.g.
/// `place(&cell, "2 / 5", "3")` spans grid columns 2 to 4 in row 3.
pub fn place(element: &Element, column: &str, row: &str) -> Result<(), JsValue> {
    let style = element.unchecked_ref::<HtmlElement>().style();
    style.set_property("grid-column", column)?;
    style.set_property("grid-row", row)?;
    Ok(())
}
