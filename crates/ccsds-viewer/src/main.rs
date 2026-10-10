//! `ccsds-viewer` - command line application that reads a file of CCSDS
//! Space Packets (hex text) and serves a web interface to inspect them.
//!
//! The web interface itself is rendered by the WebAssembly frontend
//! (`ccsds-web` crate). This binary only parses the input file and serves
//! the static web assets plus the parsed packets as JSON.

mod server;

use std::path::PathBuf;
use std::process::ExitCode;

use ccsds_common::{format_hex_bytes, PacketStream};
use clap::Parser;

/// Default location of the web assets: the `web` directory of the workspace.
const DEFAULT_WEB_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web");

/// Display CCSDS Space Packets from a hex text file in the web browser.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Input file with whitespace separated hex bytes ('#' starts a comment).
    input: PathBuf,

    /// TCP port of the web server.
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Address the web server binds to.
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Directory containing index.html, style.css and the WebAssembly
    /// package (pkg/) built with wasm-pack.
    #[arg(long, default_value = DEFAULT_WEB_ROOT)]
    web_root: PathBuf,

    /// Only print the packets to the console and exit without starting the
    /// web server.
    #[arg(long)]
    dump: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let text = match std::fs::read_to_string(&cli.input) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("error: cannot read '{}': {error}", cli.input.display());
            return ExitCode::FAILURE;
        }
    };

    let source = cli
        .input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| cli.input.display().to_string());
    let stream = PacketStream::from_hex_text(source, &text);

    print_summary(&stream, cli.dump);
    if cli.dump {
        return ExitCode::SUCCESS;
    }

    let web_root = match cli.web_root.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            eprintln!(
                "error: web root '{}' not found: {error}",
                cli.web_root.display()
            );
            return ExitCode::FAILURE;
        }
    };
    if !web_root.join("pkg").join("ccsds_web.js").is_file() {
        eprintln!(
            "warning: WebAssembly package missing in '{}'.\n         \
             Build it with: wasm-pack build crates/ccsds-web --target web --out-dir ../../web/pkg",
            web_root.join("pkg").display()
        );
    }

    let json = match serde_json::to_string(&stream) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("error: cannot serialise packets: {error}");
            return ExitCode::FAILURE;
        }
    };

    match server::serve(&cli.bind, cli.port, web_root, json) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: web server failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Prints a short overview (or, with `verbose`, every packet) to stdout.
fn print_summary(stream: &PacketStream, verbose: bool) {
    println!(
        "{}: {} valid packet(s)",
        stream.source,
        stream.packets.len()
    );

    if verbose {
        for packet in &stream.packets {
            println!(
                "  @{:<6} {:<26} header: {}  data: {}",
                packet.offset,
                packet.title(),
                format_hex_bytes(&packet.header_bytes),
                format_hex_bytes(&packet.data)
            );
        }
    }

    if let Some(invalid) = &stream.invalid {
        println!(
            "  first invalid packet at byte offset {}: {}",
            invalid.offset, invalid.reason
        );
    }
}
