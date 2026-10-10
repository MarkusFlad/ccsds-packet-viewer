//! Minimal blocking HTTP server for the web interface.
//!
//! Routes:
//! - `GET /api/packets` - the parsed packet stream as JSON
//! - `GET /<path>`      - static files from the web root (`/` maps to `index.html`)

use std::io;
use std::path::{Component, Path, PathBuf};

use tiny_http::{Header, Method, Request, Response, Server};

/// Starts the server and handles requests until the process is terminated.
pub fn serve(bind: &str, port: u16, web_root: PathBuf, packets_json: String) -> io::Result<()> {
    let address = format!("{bind}:{port}");
    let server = Server::http(&address).map_err(io::Error::other)?;

    let shown_host = if bind == "0.0.0.0" { "localhost" } else { bind };
    println!("Web interface: http://{shown_host}:{port}/  (Ctrl+C to stop)");

    for request in server.incoming_requests() {
        if let Err(error) = handle(request, &web_root, &packets_json) {
            eprintln!("warning: failed to send response: {error}");
        }
    }
    Ok(())
}

/// Handles a single request.
fn handle(request: Request, web_root: &Path, packets_json: &str) -> io::Result<()> {
    if *request.method() != Method::Get && *request.method() != Method::Head {
        return request.respond(text_response(405, "method not allowed"));
    }

    // Ignore query string and fragment.
    let url = request.url().to_string();
    let path = url.split(['?', '#']).next().unwrap_or("/");

    if path == "/api/packets" {
        let response = Response::from_string(packets_json)
            .with_header(content_type("application/json; charset=utf-8"))
            .with_header(no_cache());
        return request.respond(response);
    }

    let Some(file_path) = resolve_static_path(web_root, path) else {
        return request.respond(text_response(404, "not found"));
    };

    match std::fs::read(&file_path) {
        Ok(content) => {
            let response = Response::from_data(content)
                .with_header(content_type(mime_type(&file_path)))
                .with_header(no_cache());
            request.respond(response)
        }
        Err(_) => request.respond(text_response(404, "not found")),
    }
}

/// Maps a URL path to a file below the web root. Returns `None` for paths
/// trying to escape the web root (e.g. containing `..`).
fn resolve_static_path(web_root: &Path, url_path: &str) -> Option<PathBuf> {
    let relative = url_path.trim_start_matches('/');
    let relative = if relative.is_empty() || relative.ends_with('/') {
        format!("{relative}index.html")
    } else {
        relative.to_string()
    };

    let relative = Path::new(&relative);
    if !relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }

    let full = web_root.join(relative);
    full.is_file().then_some(full)
}

/// Content type by file extension. `application/wasm` is required for
/// streaming WebAssembly compilation in the browser.
fn mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn content_type(value: &str) -> Header {
    Header::from_bytes("Content-Type", value).expect("valid header")
}

fn no_cache() -> Header {
    Header::from_bytes("Cache-Control", "no-cache").expect("valid header")
}

fn text_response(status: u16, text: &str) -> Response<io::Cursor<Vec<u8>>> {
    Response::from_string(text)
        .with_status_code(status)
        .with_header(content_type("text/plain; charset=utf-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_directory_paths() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(resolve_static_path(root, "/../Cargo.toml"), None);
        assert_eq!(resolve_static_path(root, "/src/../../x"), None);
    }

    #[test]
    fn resolves_existing_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            resolve_static_path(root, "/Cargo.toml"),
            Some(root.join("Cargo.toml"))
        );
    }

    #[test]
    fn wasm_mime_type() {
        assert_eq!(mime_type(Path::new("pkg/x_bg.wasm")), "application/wasm");
    }
}
