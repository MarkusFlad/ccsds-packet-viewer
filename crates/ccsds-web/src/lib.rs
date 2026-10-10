//! WebAssembly frontend of the CCSDS Space Packet viewer.
//!
//! On start-up the module fetches the parsed packet stream from
//! `api/packets`, renders the overview of all packets and installs the mouse
//! handlers that show the detail view of the packet under the mouse pointer.
//!
//! All DOM manipulation happens here in Rust; the only hand written
//! JavaScript is the two line module loader in `web/index.html`.

mod detail;
mod dom;
mod overview;

use std::cell::Cell;
use std::rc::Rc;

use ccsds_common::PacketStream;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Document, Element, MouseEvent, Response, Window};

use crate::dom::create;

/// URL (relative to the page) of the JSON packet stream.
const PACKETS_URL: &str = "api/packets";

/// Entry point, called automatically when the module is instantiated.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    wasm_bindgen_futures::spawn_local(async {
        if let Err(error) = run().await {
            show_error(&describe_js_error(&error));
        }
    });
}

/// Loads the packets and builds the page.
async fn run() -> Result<(), JsValue> {
    let window = window()?;
    let document = window
        .document()
        .ok_or_else(|| JsValue::from_str("no document available"))?;

    let stream = fetch_packets(&window).await?;
    render_page(&document, Rc::new(stream))
}

/// Fetches and deserialises the packet stream from the server.
async fn fetch_packets(window: &Window) -> Result<PacketStream, JsValue> {
    let response: Response = JsFuture::from(window.fetch_with_str(PACKETS_URL))
        .await?
        .dyn_into()?;
    if !response.ok() {
        return Err(JsValue::from_str(&format!(
            "loading {PACKETS_URL} failed: HTTP {}",
            response.status()
        )));
    }

    let text = JsFuture::from(response.text()?)
        .await?
        .as_string()
        .ok_or_else(|| JsValue::from_str("packet data is not text"))?;

    serde_json::from_str(&text)
        .map_err(|error| JsValue::from_str(&format!("invalid packet data: {error}")))
}

/// State shared by the mouse event handlers.
struct ViewState {
    document: Document,
    stream: Rc<PacketStream>,
    /// The floating container that shows the detail view.
    detail: Element,
    /// Index of the packet currently shown in the detail view.
    current: Cell<Option<usize>>,
}

/// Renders summary line, overview and installs the hover handling.
fn render_page(document: &Document, stream: Rc<PacketStream>) -> Result<(), JsValue> {
    if let Some(summary) = document.get_element_by_id("summary") {
        let invalid_note = match &stream.invalid {
            Some(invalid) => format!(", invalid data at byte offset {}", invalid.offset),
            None => String::new(),
        };
        summary.set_text_content(Some(&format!(
            "{} \u{2014} {} valid packet(s){}",
            stream.source,
            stream.packets.len(),
            invalid_note
        )));
    }

    let container = document
        .get_element_by_id("packets")
        .ok_or_else(|| JsValue::from_str("element #packets missing in index.html"))?;
    overview::render(document, &container, &stream)?;

    let detail = create(document, "div", "detail-popup")?;
    detail.set_attribute("hidden", "")?;
    document
        .body()
        .ok_or_else(|| JsValue::from_str("no body element"))?
        .append_child(&detail)?;

    let state = Rc::new(ViewState {
        document: document.clone(),
        stream,
        detail,
        current: Cell::new(None),
    });
    install_hover_handlers(&container, state)
}

/// Uses event delegation on the overview container: one `mouseover` handler
/// finds the packet under the pointer, `mouseleave` hides the detail view.
fn install_hover_handlers(container: &Element, state: Rc<ViewState>) -> Result<(), JsValue> {
    let over_state = Rc::clone(&state);
    let on_mouse_over = Closure::<dyn FnMut(MouseEvent)>::new(move |event: MouseEvent| {
        let index = packet_index_of_event(&event);
        if let Err(error) = update_detail(&over_state, index) {
            show_error(&describe_js_error(&error));
        }
    });
    container
        .add_event_listener_with_callback("mouseover", on_mouse_over.as_ref().unchecked_ref())?;
    // The handler lives as long as the page, so leaking it is intended.
    on_mouse_over.forget();

    let leave_state = state;
    let on_mouse_leave = Closure::<dyn FnMut(MouseEvent)>::new(move |_event: MouseEvent| {
        if let Err(error) = update_detail(&leave_state, None) {
            show_error(&describe_js_error(&error));
        }
    });
    container
        .add_event_listener_with_callback("mouseleave", on_mouse_leave.as_ref().unchecked_ref())?;
    on_mouse_leave.forget();

    Ok(())
}

/// Returns the index of the packet element the event target belongs to.
fn packet_index_of_event(event: &MouseEvent) -> Option<usize> {
    let target: Element = event.target()?.dyn_into().ok()?;
    let packet = target.closest(".packet[data-index]").ok()??;
    packet.get_attribute("data-index")?.parse().ok()
}

/// Shows the detail view for the given packet, or hides it for `None`.
fn update_detail(state: &ViewState, index: Option<usize>) -> Result<(), JsValue> {
    if state.current.get() == index {
        return Ok(());
    }
    state.current.set(index);

    let Some(index) = index else {
        state.detail.set_attribute("hidden", "")?;
        state.detail.set_inner_html("");
        return Ok(());
    };
    let Some(packet) = state.stream.packets.get(index) else {
        return Ok(());
    };

    state.detail.set_inner_html("");
    state
        .detail
        .append_child(&detail::build(&state.document, packet)?.into())?;
    state.detail.remove_attribute("hidden")?;

    let anchor = state
        .document
        .query_selector(&format!(".packet[data-index=\"{index}\"]"))?;
    if let Some(anchor) = anchor {
        position_detail(&state.detail, &anchor)?;
    }
    Ok(())
}

/// Places the detail view slightly below and right of the top left corner of
/// the hovered packet, so that it partially covers the packets behind it,
/// while keeping it inside the visible area of the window.
fn position_detail(detail: &Element, anchor: &Element) -> Result<(), JsValue> {
    const OFFSET_X: f64 = 16.0;
    const OFFSET_Y: f64 = 28.0;
    const MARGIN: f64 = 8.0;

    let window = window()?;
    let scroll_x = window.scroll_x()?;
    let scroll_y = window.scroll_y()?;
    let view_width = window.inner_width()?.as_f64().unwrap_or(1024.0);
    let view_height = window.inner_height()?.as_f64().unwrap_or(768.0);

    let rect = anchor.get_bounding_client_rect();
    let detail_rect = detail.get_bounding_client_rect();

    let mut left = rect.left() + OFFSET_X;
    let mut top = rect.top() + OFFSET_Y;
    left = left
        .min(view_width - detail_rect.width() - MARGIN)
        .max(MARGIN);
    top = top
        .min(view_height - detail_rect.height() - MARGIN)
        .max(MARGIN);

    let element: &web_sys::HtmlElement = detail.unchecked_ref();
    let style = element.style();
    style.set_property("left", &format!("{}px", left + scroll_x))?;
    style.set_property("top", &format!("{}px", top + scroll_y))?;
    Ok(())
}

fn window() -> Result<Window, JsValue> {
    web_sys::window().ok_or_else(|| JsValue::from_str("no window available"))
}

/// Displays an error message in the summary line of the page.
fn show_error(message: &str) {
    let Some(document) = web_sys::window().and_then(|window| window.document()) else {
        return;
    };
    if let Some(summary) = document.get_element_by_id("summary") {
        summary.set_class_name("summary error");
        summary.set_text_content(Some(&format!("Error: {message}")));
    }
}

/// Converts a JavaScript error value into readable text.
fn describe_js_error(error: &JsValue) -> String {
    error.as_string().unwrap_or_else(|| format!("{error:?}"))
}
