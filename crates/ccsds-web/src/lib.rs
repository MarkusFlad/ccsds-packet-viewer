//! WebAssembly frontend of the CCSDS viewer.
//!
//! On start-up the module fetches the parsed stream (Space Packets, TM or TC
//! Transfer Frames) from `api/stream` and renders the page selected by the
//! URL hash (see [`pages::Route`]).
//!
//! Interaction:
//! - Hovering over an item shows its detail view as a preview.
//! - Clicking an item pins the detail view: it stays open and its links can
//!   be clicked. A click outside or the Escape key closes it.
//! - In a pinned frame detail view, the packets in the data field are
//!   links to the page with the Space Packets of that frame; the heading of
//!   that page links back to the frame.
//!
//! All DOM manipulation happens here in Rust; the only hand written
//! JavaScript is the two line module loader in `web/index.html`.

mod dom;
mod frame_view;
mod layout;
mod packet_view;
mod pages;
mod tc_frame_view;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ccsds_common::Stream;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Document, Element, Event, HtmlElement, KeyboardEvent, MouseEvent, Response, Window};

use crate::dom::{create, create_text};
use crate::layout::{render_detail, render_invalid, render_overview_box, DetailLayout};
use crate::pages::{PageModel, Route};

/// URL (relative to the page) of the JSON stream.
const STREAM_URL: &str = "api/stream";

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

/// Loads the stream, renders the current page and installs the handlers.
async fn run() -> Result<(), JsValue> {
    let window = window()?;
    let document = window
        .document()
        .ok_or_else(|| JsValue::from_str("no document available"))?;

    let stream = fetch_stream(&window).await?;

    let container = document
        .get_element_by_id("packets")
        .ok_or_else(|| JsValue::from_str("element #packets missing in index.html"))?;
    let detail = create(&document, "div", "detail-popup")?;
    detail.set_attribute("hidden", "")?;
    document
        .body()
        .ok_or_else(|| JsValue::from_str("no body element"))?
        .append_child(&detail)?;

    let app = Rc::new(App {
        window,
        document,
        stream,
        container,
        detail,
        details: RefCell::new(Vec::new()),
        shown: Cell::new(None),
        pinned: Cell::new(false),
    });

    app.render_current_route()?;
    install_handlers(&app)
}

/// Fetches and deserialises the stream from the server.
async fn fetch_stream(window: &Window) -> Result<Stream, JsValue> {
    let response: Response = JsFuture::from(window.fetch_with_str(STREAM_URL))
        .await?
        .dyn_into()?;
    if !response.ok() {
        return Err(JsValue::from_str(&format!(
            "loading {STREAM_URL} failed: HTTP {}",
            response.status()
        )));
    }

    let text = JsFuture::from(response.text()?)
        .await?
        .as_string()
        .ok_or_else(|| JsValue::from_str("stream data is not text"))?;

    serde_json::from_str(&text)
        .map_err(|error| JsValue::from_str(&format!("invalid stream data: {error}")))
}

/// Application state shared by all event handlers.
struct App {
    window: Window,
    document: Document,
    stream: Stream,
    /// Container of the overview boxes (`#packets`).
    container: Element,
    /// Floating container of the detail view.
    detail: Element,
    /// Detail views of the current page (index = `data-index` of the box).
    details: RefCell<Vec<DetailLayout>>,
    /// Index of the item whose detail view is shown.
    shown: Cell<Option<usize>>,
    /// The detail view is pinned (stays open, links are clickable).
    pinned: Cell<bool>,
}

impl App {
    /// Renders the page for the current URL hash.
    fn render_current_route(&self) -> Result<(), JsValue> {
        let hash = self.window.location().hash()?;
        let page = pages::build(&self.stream, Route::parse(&hash));
        self.render_page(page)
    }

    /// Replaces the page content.
    fn render_page(&self, page: PageModel) -> Result<(), JsValue> {
        self.hide_detail()?;

        if let Some(heading) = self.document.get_element_by_id("heading") {
            heading.set_inner_html("");
            match &page.heading {
                Some((text, href)) => {
                    let link = create_text(&self.document, "a", "frame-link", text)?;
                    link.set_attribute("href", href)?;
                    link.set_attribute("title", "back to the frame")?;
                    heading.append_child(&link)?;
                    heading.remove_attribute("hidden")?;
                }
                None => heading.set_attribute("hidden", "")?,
            }
        }
        if let Some(summary) = self.document.get_element_by_id("summary") {
            summary.set_class_name("summary");
            summary.set_text_content(Some(&page.summary));
        }

        self.container.set_inner_html("");
        for (index, model) in page.boxes.iter().enumerate() {
            let element = render_overview_box(&self.document, index, model)?;
            self.container.append_child(&element)?;
        }
        if let Some((text, reason)) = &page.invalid {
            self.container
                .append_child(&render_invalid(&self.document, text, reason)?.into())?;
        }

        *self.details.borrow_mut() = page.details;

        match page.pin {
            Some(index) => {
                if let Some(anchor) = self.box_element(index)? {
                    anchor.scroll_into_view();
                }
                self.show_detail(index)?;
                self.set_pinned(true)?;
            }
            None => self.window.scroll_to_with_x_and_y(0.0, 0.0),
        }
        Ok(())
    }

    /// The overview box with the given index.
    fn box_element(&self, index: usize) -> Result<Option<Element>, JsValue> {
        self.container
            .query_selector(&format!(".packet[data-index=\"{index}\"]"))
    }

    /// Shows the detail view of an item (unless it is already shown).
    fn show_detail(&self, index: usize) -> Result<(), JsValue> {
        if self.shown.get() == Some(index) {
            return Ok(());
        }
        let details = self.details.borrow();
        let Some(layout) = details.get(index) else {
            return self.hide_detail();
        };

        self.detail.set_inner_html("");
        self.detail
            .append_child(&render_detail(&self.document, layout)?.into())?;
        self.detail.remove_attribute("hidden")?;
        self.shown.set(Some(index));

        if let Some(anchor) = self.box_element(index)? {
            position_detail(&self.window, &self.detail, &anchor)?;
        }
        Ok(())
    }

    /// Hides and unpins the detail view.
    fn hide_detail(&self) -> Result<(), JsValue> {
        self.set_pinned(false)?;
        self.shown.set(None);
        self.detail.set_attribute("hidden", "")?;
        self.detail.set_inner_html("");
        Ok(())
    }

    fn set_pinned(&self, pinned: bool) -> Result<(), JsValue> {
        self.pinned.set(pinned);
        self.detail
            .class_list()
            .toggle_with_force("pinned", pinned)?;
        Ok(())
    }

    /// Mouse moved over the overview (hover preview).
    fn on_mouse_over(&self, event: &MouseEvent) -> Result<(), JsValue> {
        if self.pinned.get() {
            return Ok(());
        }
        match item_index_of_event(event) {
            Some(index) => self.show_detail(index),
            None => self.hide_detail(),
        }
    }

    /// Mouse left the overview.
    fn on_mouse_leave(&self) -> Result<(), JsValue> {
        if self.pinned.get() {
            return Ok(());
        }
        self.hide_detail()
    }

    /// Click anywhere on the page: pin the clicked item, keep the pinned view
    /// when clicking inside it, otherwise close it.
    fn on_click(&self, event: &MouseEvent) -> Result<(), JsValue> {
        let Some(target) = event_element(event) else {
            return Ok(());
        };
        if target.closest(".detail-popup")?.is_some() {
            // Links inside the detail view navigate via the URL hash.
            return Ok(());
        }
        match item_index_of_event(event) {
            Some(index) => {
                if self.pinned.get() && self.shown.get() == Some(index) {
                    return self.hide_detail();
                }
                self.set_pinned(false)?;
                self.show_detail(index)?;
                self.set_pinned(true)
            }
            None => self.hide_detail(),
        }
    }

    fn on_key_down(&self, event: &KeyboardEvent) -> Result<(), JsValue> {
        if event.key() == "Escape" {
            self.hide_detail()?;
        }
        Ok(())
    }
}

/// Installs all event handlers. They live as long as the page, so the
/// closures are intentionally leaked with `forget`.
fn install_handlers(app: &Rc<App>) -> Result<(), JsValue> {
    let state = Rc::clone(app);
    let on_mouse_over = Closure::<dyn FnMut(MouseEvent)>::new(move |event: MouseEvent| {
        report(state.on_mouse_over(&event));
    });
    app.container
        .add_event_listener_with_callback("mouseover", on_mouse_over.as_ref().unchecked_ref())?;
    on_mouse_over.forget();

    let state = Rc::clone(app);
    let on_mouse_leave = Closure::<dyn FnMut(MouseEvent)>::new(move |_event: MouseEvent| {
        report(state.on_mouse_leave());
    });
    app.container
        .add_event_listener_with_callback("mouseleave", on_mouse_leave.as_ref().unchecked_ref())?;
    on_mouse_leave.forget();

    let state = Rc::clone(app);
    let on_click = Closure::<dyn FnMut(MouseEvent)>::new(move |event: MouseEvent| {
        report(state.on_click(&event));
    });
    app.document
        .add_event_listener_with_callback("click", on_click.as_ref().unchecked_ref())?;
    on_click.forget();

    let state = Rc::clone(app);
    let on_key_down = Closure::<dyn FnMut(KeyboardEvent)>::new(move |event: KeyboardEvent| {
        report(state.on_key_down(&event));
    });
    app.document
        .add_event_listener_with_callback("keydown", on_key_down.as_ref().unchecked_ref())?;
    on_key_down.forget();

    let state = Rc::clone(app);
    let on_hash_change = Closure::<dyn FnMut(Event)>::new(move |_event: Event| {
        report(state.render_current_route());
    });
    app.window
        .add_event_listener_with_callback("hashchange", on_hash_change.as_ref().unchecked_ref())?;
    on_hash_change.forget();

    Ok(())
}

/// The element an event was dispatched to.
fn event_element(event: &MouseEvent) -> Option<Element> {
    event.target()?.dyn_into().ok()
}

/// Returns the index of the overview box the event target belongs to.
fn item_index_of_event(event: &MouseEvent) -> Option<usize> {
    let item = event_element(event)?
        .closest("#packets .packet[data-index]")
        .ok()??;
    item.get_attribute("data-index")?.parse().ok()
}

/// Places the detail view slightly below and right of the top left corner of
/// the item, so that it partially covers the items behind it, while keeping
/// it inside the visible area of the window. A detail view wider than the
/// window (e.g. a TM frame with many fields) is scaled down to fit.
fn position_detail(window: &Window, detail: &Element, anchor: &Element) -> Result<(), JsValue> {
    const OFFSET_X: f64 = 16.0;
    const OFFSET_Y: f64 = 28.0;
    const MARGIN: f64 = 8.0;

    let scroll_x = window.scroll_x()?;
    let scroll_y = window.scroll_y()?;
    let view_width = window.inner_width()?.as_f64().unwrap_or(1024.0);
    let view_height = window.inner_height()?.as_f64().unwrap_or(768.0);

    let element: &HtmlElement = detail.unchecked_ref();
    let style = element.style();

    // Natural size (offset sizes ignore transforms).
    let natural_width = f64::from(element.offset_width());
    let natural_height = f64::from(element.offset_height());
    let scale = if natural_width > 0.0 {
        ((view_width - 2.0 * MARGIN) / natural_width).min(1.0)
    } else {
        1.0
    };
    if scale < 1.0 {
        style.set_property("transform", &format!("scale({scale:.4})"))?;
    } else {
        style.remove_property("transform")?;
    }
    let width = natural_width * scale;
    let height = natural_height * scale;

    let rect = anchor.get_bounding_client_rect();
    let left = (rect.left() + OFFSET_X)
        .min(view_width - width - MARGIN)
        .max(MARGIN);
    let top = (rect.top() + OFFSET_Y)
        .min(view_height - height - MARGIN)
        .max(MARGIN);

    style.set_property("left", &format!("{}px", left + scroll_x))?;
    style.set_property("top", &format!("{}px", top + scroll_y))?;
    Ok(())
}

fn window() -> Result<Window, JsValue> {
    web_sys::window().ok_or_else(|| JsValue::from_str("no window available"))
}

/// Shows errors of event handlers in the summary line.
fn report(result: Result<(), JsValue>) {
    if let Err(error) = result {
        show_error(&describe_js_error(&error));
    }
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

#[cfg(test)]
mod tests {
    use super::pages::Route;

    #[test]
    fn parses_routes() {
        assert_eq!(Route::parse(""), Route::Overview { pin: None });
        assert_eq!(Route::parse("#/"), Route::Overview { pin: None });
        assert_eq!(Route::parse("#/frame/3"), Route::Overview { pin: Some(3) });
        assert_eq!(Route::parse("#/frame/3/packets"), Route::FramePackets(3));
        assert_eq!(
            Route::parse("#/frame/x/packets"),
            Route::Overview { pin: None }
        );
        assert_eq!(Route::parse("#/unknown"), Route::Overview { pin: None });
    }
}
