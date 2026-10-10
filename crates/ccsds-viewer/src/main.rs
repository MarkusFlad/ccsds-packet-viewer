//! `ccsds-viewer` - command line application that reads a file of CCSDS
//! Space Packets, CCSDS TM Transfer Frames or CCSDS TC Transfer Frames (hex
//! text) and serves a web interface to inspect them.
//!
//! The web interface itself is rendered by the WebAssembly frontend
//! (`ccsds-web` crate). This binary only parses the input file and serves
//! the static web assets plus the parsed stream as JSON.

mod server;

use std::path::PathBuf;
use std::process::ExitCode;

use ccsds_common::{
    format_hex_bytes, parse_hex_text, FrameStream, PacketStream, SdlsConfig, Stream, TcFrameConfig,
    TcFrameStream, TmFrameConfig, DEFAULT_ASM,
};
use clap::{Parser, ValueEnum};

/// Default location of the web assets: the `web` directory of the workspace.
const DEFAULT_WEB_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web");

/// Kind of data contained in the input file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// CCSDS Space Packets (CCSDS 133.0-B)
    Packets,
    /// CCSDS TM Transfer Frames (CCSDS 132.0-B)
    TmFrames,
    /// CCSDS TC Transfer Frames (CCSDS 232.0-B)
    TcFrames,
}

/// Display CCSDS Space Packets, TM Transfer Frames or TC Transfer Frames
/// from a hex text file in the web browser.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Input file with whitespace separated hex bytes ('#' starts a comment).
    input: PathBuf,

    /// Kind of data in the input file.
    #[arg(short, long, value_enum, default_value_t = Mode::Packets)]
    mode: Mode,

    /// TM frames: total length of every Transfer Frame in octets
    /// (without Attached Sync Marker). Required with `--mode tm-frames`.
    #[arg(short = 'l', long, value_name = "OCTETS")]
    frame_length: Option<usize>,

    /// Frames: every frame ends with a 2 octet Frame Error Control Field.
    #[arg(long)]
    fecf: bool,

    /// Frames: show frames with a wrong FECF instead of treating them as
    /// invalid.
    #[arg(long, requires = "fecf")]
    ignore_crc: bool,

    /// TM frames: every frame is preceded by an Attached Sync Marker. Without
    /// a value the standard marker 1acffc1d is used.
    #[arg(
        long,
        value_name = "HEX",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "1acffc1d"
    )]
    asm: Option<String>,

    /// TC frames: every frame carrying data starts its data field with a
    /// 1 octet Segment Header.
    #[arg(long)]
    segment_header: bool,

    /// Frames: every frame carries a Security Header of the Space Data
    /// Link Security Protocol with this length (at least 2 octets).
    #[arg(long, value_name = "OCTETS")]
    sdls_header: Option<usize>,

    /// SDLS: length of the Security Trailer. Without this option the frames
    /// have no Security Trailer.
    #[arg(
        long,
        value_name = "OCTETS",
        default_value_t = 0,
        requires = "sdls_header"
    )]
    sdls_trailer: usize,

    /// SDLS: the Transfer Frame Data Field is encrypted, do not extract
    /// Space Packets from it.
    #[arg(long, requires = "sdls_header")]
    sdls_encrypted: bool,

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

    /// Only print the stream to the console and exit without starting the
    /// web server.
    #[arg(long)]
    dump: bool,
}

impl Cli {
    /// Builds the TM frame configuration from the command line options.
    fn frame_config(&self) -> Result<TmFrameConfig, String> {
        let frame_length = self
            .frame_length
            .ok_or("--frame-length is required with --mode tm-frames")?;

        let asm = match &self.asm {
            None => None,
            Some(hex) => Some(parse_asm(hex)?),
        };

        if self.segment_header {
            return Err("--segment-header requires --mode tc-frames".into());
        }

        let config = TmFrameConfig {
            frame_length,
            fecf_present: self.fecf,
            check_crc: !self.ignore_crc,
            asm,
            sdls: self.sdls_config(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Builds the TC frame configuration from the command line options.
    fn tc_frame_config(&self) -> Result<TcFrameConfig, String> {
        if self.frame_length.is_some() || self.asm.is_some() {
            return Err("--frame-length and --asm require --mode tm-frames".into());
        }

        let config = TcFrameConfig {
            segment_header: self.segment_header,
            fecf_present: self.fecf,
            check_crc: !self.ignore_crc,
            sdls: self.sdls_config(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Space Data Link Security Protocol parameters, if `--sdls-header` is
    /// given.
    fn sdls_config(&self) -> Option<SdlsConfig> {
        self.sdls_header.map(|header_length| SdlsConfig {
            header_length,
            trailer_length: self.sdls_trailer,
            encrypted: self.sdls_encrypted,
        })
    }

    /// Rejects frame options when reading Space Packets.
    fn check_packet_options(&self) -> Result<(), String> {
        let frame_options_used = self.frame_length.is_some()
            || self.fecf
            || self.ignore_crc
            || self.asm.is_some()
            || self.segment_header
            || self.sdls_header.is_some();
        if frame_options_used {
            return Err(
                "--frame-length, --fecf, --ignore-crc, --asm, --segment-header and --sdls-header \
                 require --mode tm-frames or --mode tc-frames"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Parses the ASM given as hex digits, e.g. `1acffc1d` or `1a cf fc 1d`.
fn parse_asm(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() || digits.len() % 2 != 0 {
        return Err(format!(
            "invalid --asm value '{text}': expected an even number of hex digits"
        ));
    }
    let spaced: Vec<&str> = (0..digits.len())
        .step_by(2)
        .map(|i| &digits[i..i + 2])
        .collect();
    match parse_hex_text(&spaced.join(" ")) {
        (bytes, None) => Ok(bytes),
        (_, Some(_)) => Err(format!(
            "invalid --asm value '{text}': expected hex digits, e.g. {}",
            format_hex_bytes(&DEFAULT_ASM).replace(' ', "")
        )),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    let text = std::fs::read_to_string(&cli.input)
        .map_err(|error| format!("cannot read '{}': {error}", cli.input.display()))?;

    let source = cli
        .input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| cli.input.display().to_string());

    let stream = match cli.mode {
        Mode::Packets => {
            cli.check_packet_options()?;
            Stream::Packets(PacketStream::from_hex_text(source, &text))
        }
        Mode::TmFrames => {
            let config = cli.frame_config()?;
            Stream::TmFrames(FrameStream::from_hex_text(source, &text, config))
        }
        Mode::TcFrames => {
            let config = cli.tc_frame_config()?;
            Stream::TcFrames(TcFrameStream::from_hex_text(source, &text, config))
        }
    };

    print_summary(&stream, cli.dump);
    if cli.dump {
        return Ok(());
    }

    let web_root = cli
        .web_root
        .canonicalize()
        .map_err(|error| format!("web root '{}' not found: {error}", cli.web_root.display()))?;
    if !web_root.join("pkg").join("ccsds_web.js").is_file() {
        eprintln!(
            "warning: WebAssembly package missing in '{}'.\n         \
             Build it with: wasm-pack build crates/ccsds-web --target web --out-dir ../../web/pkg",
            web_root.join("pkg").display()
        );
    }

    let json = serde_json::to_string(&stream)
        .map_err(|error| format!("cannot serialise stream: {error}"))?;

    server::serve(&cli.bind, cli.port, web_root, json)
        .map_err(|error| format!("web server failed: {error}"))
}

/// Prints a short overview (or, with `verbose`, every item) to stdout.
fn print_summary(stream: &Stream, verbose: bool) {
    println!(
        "{}: {} valid {}",
        stream.source(),
        stream.len(),
        stream.item_name()
    );

    if verbose {
        match stream {
            Stream::Packets(stream) => {
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
            Stream::TmFrames(stream) => {
                for frame in &stream.frames {
                    let secondary = frame
                        .secondary_header
                        .as_ref()
                        .map(|sec| format!("  secondary: {}", format_hex_bytes(&sec.bytes)))
                        .unwrap_or_default();
                    let security_header = frame
                        .security_header
                        .as_ref()
                        .map(|sec| format!("  security header: {}", format_hex_bytes(sec)))
                        .unwrap_or_default();
                    let security_trailer = frame
                        .security_trailer
                        .as_ref()
                        .map(|sec| format!("  security trailer: {}", format_hex_bytes(sec)))
                        .unwrap_or_default();
                    let crc = match frame.fecf {
                        Some(fecf) if !fecf.is_ok() => "  (FECF mismatch)",
                        _ => "",
                    };
                    println!(
                        "  @{:<6} {:<35} header: {}{}{}  data: {} octets{}  trailer: {}{}",
                        frame.offset,
                        frame.title(),
                        format_hex_bytes(&frame.header_bytes),
                        secondary,
                        security_header,
                        frame.data.len(),
                        security_trailer,
                        format_hex_bytes(&frame.trailer_bytes),
                        crc
                    );
                }
            }
            Stream::TcFrames(stream) => {
                for frame in &stream.frames {
                    let segment = frame
                        .segment_header
                        .map(|segment| {
                            format!(
                                "  segment: {:02x} (MAP {}, {})",
                                segment.octet(),
                                segment.map_id,
                                segment.sequence_flags_note()
                            )
                        })
                        .unwrap_or_default();
                    let security_header = frame
                        .security_header
                        .as_ref()
                        .map(|sec| format!("  security header: {}", format_hex_bytes(sec)))
                        .unwrap_or_default();
                    let security_trailer = frame
                        .security_trailer
                        .as_ref()
                        .map(|sec| format!("  security trailer: {}", format_hex_bytes(sec)))
                        .unwrap_or_default();
                    let control = frame
                        .control_command()
                        .map(|name| format!(" ({name})"))
                        .unwrap_or_default();
                    let fecf = match frame.fecf {
                        Some(fecf) if !fecf.is_ok() => {
                            format!("  fecf: {:04x} (FECF mismatch)", fecf.value)
                        }
                        Some(fecf) => format!("  fecf: {:04x}", fecf.value),
                        None => String::new(),
                    };
                    println!(
                        "  @{:<6} {:<33} {} N(S)={:<3} header: {}{}{}  data: {} octets{}{}{}",
                        frame.offset,
                        frame.title(),
                        frame.header.frame_type(),
                        frame.header.frame_sequence_number,
                        format_hex_bytes(&frame.header_bytes),
                        segment,
                        security_header,
                        frame.data.len(),
                        control,
                        security_trailer,
                        fecf
                    );
                }
            }
        }
    }

    if stream.is_encrypted() {
        println!("  frame data fields are encrypted, no Space Packets extracted");
    } else if let Some(extraction) = stream.extraction() {
        println!(
            "  {} Space Packet(s) extracted from the frame data fields",
            extraction.complete_count()
        );
        if verbose {
            for extracted in &extraction.packets {
                match (&extracted.packet, &extracted.error) {
                    (Some(packet), _) => println!(
                        "    {:<26} frames {:?}  data: {}",
                        packet.title(),
                        extracted.frames,
                        format_hex_bytes(&packet.data)
                    ),
                    (None, Some(error)) => println!(
                        "    incomplete packet       frames {:?}  {}",
                        extracted.frames, error
                    ),
                    (None, None) => {}
                }
            }
        }
    }

    if let Some(invalid) = stream.invalid() {
        println!(
            "  first invalid item at byte offset {}: {}",
            invalid.offset, invalid.reason
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asm_values() {
        assert_eq!(parse_asm("1acffc1d").unwrap(), DEFAULT_ASM.to_vec());
        assert_eq!(parse_asm("1A CF FC 1D").unwrap(), DEFAULT_ASM.to_vec());
        assert!(parse_asm("1acff").is_err());
        assert!(parse_asm("zz").is_err());
    }

    #[test]
    fn frame_mode_requires_frame_length() {
        let cli = Cli::parse_from(["ccsds-viewer", "--mode", "tm-frames", "x.txt"]);
        assert!(cli.frame_config().is_err());
    }

    #[test]
    fn frame_options_rejected_for_packets() {
        let cli = Cli::parse_from(["ccsds-viewer", "--fecf", "x.txt"]);
        assert!(cli.check_packet_options().is_err());
    }

    #[test]
    fn sdls_options_build_the_security_config() {
        let cli = Cli::parse_from([
            "ccsds-viewer",
            "-m",
            "tm-frames",
            "-l",
            "96",
            "--sdls-header",
            "6",
            "--sdls-trailer",
            "16",
            "x.txt",
        ]);
        assert_eq!(
            cli.frame_config().unwrap().sdls,
            Some(SdlsConfig {
                header_length: 6,
                trailer_length: 16,
                encrypted: false,
            })
        );

        let plain = Cli::parse_from(["ccsds-viewer", "-m", "tm-frames", "-l", "96", "x.txt"]);
        assert_eq!(plain.frame_config().unwrap().sdls, None);

        let without_header = Cli::try_parse_from(["ccsds-viewer", "--sdls-trailer", "16", "x.txt"]);
        assert!(without_header.is_err());
    }

    #[test]
    fn tc_options_build_the_tc_config() {
        let cli = Cli::parse_from([
            "ccsds-viewer",
            "-m",
            "tc-frames",
            "--fecf",
            "--segment-header",
            "--sdls-header",
            "6",
            "x.txt",
        ]);
        let config = cli.tc_frame_config().unwrap();
        assert!(config.segment_header);
        assert!(config.fecf_present);
        assert!(config.check_crc);
        assert_eq!(config.sdls.unwrap().header_length, 6);
    }

    #[test]
    fn tm_only_and_tc_only_options_are_rejected_in_the_other_mode() {
        let tc = Cli::parse_from(["ccsds-viewer", "-m", "tc-frames", "-l", "64", "x.txt"]);
        assert!(tc.tc_frame_config().is_err());
        let tc = Cli::parse_from(["ccsds-viewer", "-m", "tc-frames", "--asm", "x.txt"]);
        assert!(tc.tc_frame_config().is_err());

        let tm = Cli::parse_from([
            "ccsds-viewer",
            "-m",
            "tm-frames",
            "-l",
            "64",
            "--segment-header",
            "x.txt",
        ]);
        assert!(tm.frame_config().is_err());
    }

    #[test]
    fn asm_flag_without_value_uses_default() {
        let cli = Cli::parse_from([
            "ccsds-viewer",
            "-m",
            "tm-frames",
            "-l",
            "64",
            "--asm",
            "x.txt",
        ]);
        assert_eq!(cli.frame_config().unwrap().asm, Some(DEFAULT_ASM.to_vec()));
    }
}
