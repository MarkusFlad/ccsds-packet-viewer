# CCSDS Space Packet & TM Frame Viewer

A command line application written entirely in Rust that reads a stream of
[CCSDS Space Packets](https://public.ccsds.org/Pubs/133x0b2e2.pdf)
(CCSDS 133.0-B-2) or of
[CCSDS TM Transfer Frames](https://public.ccsds.org/Pubs/132x0b3.pdf)
(CCSDS 132.0-B-3) from a hex text file and shows them in the web browser.
The kind of input is selected with `--mode`.
The interactive parts of the web interface are implemented in Rust and
compiled to WebAssembly.

## Features

- **Overview** of all packets of the stream, placed next to each other and
  wrapped into the next line when the window is too narrow. Every packet is
  framed with the title `TM Space Packet APID=47` / `TC Space Packet APID=100`
  (depending on the *Packet Type* bit) and shows the *Packet Primary Header*
  and the *Packet Data Field* as hex bytes (`08 2f c0 01 00 0f`).
- **Detail view**: hovering over a packet shows the full breakdown of the
  packet in the foreground, partially covering the packets behind it:

  ```text
  +--------------------------------------------------------------------------------------+
  |                               TM Space Packet APID=47                                |
  +------------------------------------------------------------------------+-------------+
  |                         Packet Primary Header                          | Packet Data |
  +---------+---------------------------+-------------------------+--------+    Field    |
  |  Packet |   Packet Identification   | Packet Sequence Control | Packet |             |
  | Version +---------------------------+-------------------------+  Data  |             |
  |  Number |           0x082f          |          0xc001         | Length |             |
  |         +------+---------+----------+---------+---------------+        |             |
  |         | Type | Sec.Hdr |   APID   | Sequence| Sequence Count|        |             |
  |         |      |   Flag  |          |  Flags  | or Packet Name|        |             |
  +---------+------+---------+----------+---------+---------------+--------+-------------+
  |    0    |  0   |    1    |    47    |    3    |       1       |   15   | 20 03 19 .. |
  |         |      |         |  0x02f   |         |     0x0001    | 0x000f |             |
  +---------+------+---------+----------+---------+---------------+--------+-------------+
  ```

  - Field values are shown in decimal; fields that can hold values greater
    than 9 additionally show the value in hex with `0x` prefix (zero padded
    to the field width).
  - *Packet Identification* (13 bits: Packet Type, Secondary Header Flag,
    APID) and *Packet Sequence Control* (16 bits: Sequence Flags, Packet
    Sequence Count) are shown in hex only.
  - Fields without a parent group (*Packet Version Number*, *Packet Data
    Length*) extend their name cell over the group rows.
- **Invalid data**: all valid packets are displayed; the first part of the
  stream that is not a valid packet is shown as a red frame with the text
  `No valid Packet-Data` (plus the byte offset and the reason). Packets after
  it are not displayed.

A packet is considered valid if

1. at least 6 bytes (the Packet Primary Header) are available,
2. the Packet Version Number is `0` (binary `000`), and
3. the complete Packet Data Field (`Packet Data Length + 1` bytes) is
   available.

## TM Transfer Frames (`--mode tm-frames`)

TM frames are displayed in the same way as Space Packets:

- **Overview**: title `TM Transfer Frame SCID=42 VCID=1` and the top level
  parts of the frame as hex bytes: *Transfer Frame Primary Header*,
  *Transfer Frame Secondary Header* (only if present), *Transfer Frame Data
  Field* and *Transfer Frame Trailer* (only if OCF and/or FECF are present).
- **Detail view** on mouse over, with the same row structure as for packets
  (title, parts, group titles, group values in hex, field names, values):

  | Part | Groups (hex only) | Fields |
  |------|-------------------|--------|
  | Primary Header | *Master Channel Identifier*, *Transfer Frame Data Field Status* | Version Number, Spacecraft Identifier, Virtual Channel Identifier, OCF Flag, Master/Virtual Channel Frame Count, Secondary Header Flag, Synchronization Flag, Packet Order Flag, Segment Length Identifier, First Header Pointer |
  | Secondary Header | *Transfer Frame Secondary Header Identification* | Version Number, Length, Secondary Header Data Field |
  | Data Field | | hex bytes |
  | Trailer | | Operational Control Field, Frame Error Control Field |

  The First Header Pointer values `0x7ff` (no packet start) and `0x7fe`
  (idle data only) are annotated; the FECF shows *CRC ok* or *CRC error*
  with the computed value. Detail views wider than the window are scaled
  down to fit.
- **Invalid data**: the first invalid frame is shown as a red frame with the
  text `No valid Frame-Data`.

### Optional parts

| Part | How its presence is determined |
|------|--------------------------------|
| Attached Sync Marker before every frame | `--asm` (standard marker `1acffc1d`) or `--asm=<HEX>` |
| Transfer Frame Secondary Header | *Secondary Header Flag* in the primary header; length from its identification octet |
| Operational Control Field | *OCF Flag* in the primary header |
| Frame Error Control Field | `--fecf` (managed parameter, not signalled in the frame) |

The frame length is a managed parameter of the physical channel as well and
must be given with `--frame-length`.

A frame is considered valid if

1. the Attached Sync Marker matches (if `--asm` is given),
2. the complete frame (`--frame-length` octets) is available,
3. the Transfer Frame Version Number is `0` (binary `00`),
4. Secondary Header and trailer leave room for at least one data octet, and
5. the FECF matches the CRC (CRC-16-CCITT, preset `0xffff`) computed over
   the frame, if `--fecf` is given. With `--ignore-crc` frames with a wrong
   FECF are displayed anyway (marked *CRC error* in the detail view).

### Space Packets inside the frames

The Space Packets contained in the data fields are reassembled per virtual
channel (Spacecraft ID + Virtual Channel ID), also when a packet (or even
its primary header) is split over several frames:

1. **Hover** over a frame shows its detail view as a preview.
2. **Click** on a frame pins the detail view (it stays open; click outside
   or press Escape to close it). In the *Transfer Frame Data Field* every
   packet part is highlighted in alternating colours; a bar marks where a
   packet header starts (the first one is the one addressed by the First
   Header Pointer). When the mouse is over the data field, the packet parts
   are shown as **links**.
3. A link opens the page with the **Space Packets that start in that frame**
   (`#/frame/<n>/packets`), displayed like a packet stream, with hover and
   pinned detail views. Packets continuing in later frames are shown
   completely. A continuation at the beginning of a data field links to the
   frame in which its packet starts.
4. The heading of that page is the frame identification
   (`TM Transfer Frame SCID=42 VCID=1 MCFC=1 VCFC=1`) and a link back to the
   frame overview with the detail view of this frame pinned
   (`#/frame/<n>`). The browser back button works as well.

The reassembly of a virtual channel is interrupted (the packet in progress
is shown as `No valid Packet-Data` on its packet page) by a gap in the
Virtual Channel Frame Count, a frame with a FECF mismatch (`--ignore-crc`),
a frame with Synchronization Flag 1, a First Header Pointer inside the
packet in progress, or the end of the stream. Data before the next First
Header Pointer is marked as not assigned; idle frames (First Header Pointer
`0x7fe`) are marked as idle data.

## Project structure

```text
ccsds-packet-viewer/
├── Cargo.toml                  workspace
├── crates/
│   ├── ccsds-common/           packet and TM frame models, parsers, CRC, packet
│   │                           extraction from frames, hex formatting (+ unit tests)
│   ├── ccsds-viewer/           CLI binary: reads the file, serves the web UI
│   └── ccsds-web/              WebAssembly frontend: renders overview + detail view
│       └── src/
│           ├── lib.rs          start-up, routing, hover/pin/click handling
│           ├── pages.rs        URL hash routes and page models
│           ├── layout.rs       generic view model + rendering of framed views
│           ├── packet_view.rs  Space Packet -> view model
│           └── frame_view.rs   TM Transfer Frame -> view model
├── web/
│   ├── index.html              page skeleton + 2-line WebAssembly loader
│   ├── style.css               frames and layout
│   └── pkg/                    generated by wasm-pack (not in version control)
└── data/
    ├── example.txt             7 valid packets followed by a truncated packet
    ├── example_valid.txt       7 valid packets only
    ├── example_bad_version.txt invalid Packet Version Number in the 4th packet
    ├── tm_frames.txt           6 TM frames (64 octets, FECF; OCF, secondary header,
    │                           idle frame) followed by a frame with a CRC error
    └── tm_frames_asm.txt       3 TM frames (48 octets, OCF) each preceded by an ASM
```

`ccsds-common` is used by both the native CLI and the WebAssembly frontend,
so parsing and number formatting exist only once.

### About JavaScript

Browsers can only instantiate WebAssembly modules from JavaScript. The only
hand written JavaScript is therefore the two line module loader in
`web/index.html`. The glue code in `web/pkg/` is generated by
`wasm-bindgen`. All DOM construction, event handling and positioning of the
detail view is written in Rust (`crates/ccsds-web`).

## Prerequisites

- Rust 1.77 or newer (`rustup` recommended)
- WebAssembly target: `rustup target add wasm32-unknown-unknown`
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/): `cargo install wasm-pack`

## Build and run

```sh
# 1. Build the WebAssembly frontend into web/pkg
wasm-pack build crates/ccsds-web --target web --release --out-dir ../../web/pkg --no-typescript

# 2. Build and start the viewer with Space Packets ...
cargo run --release -p ccsds-viewer -- data/example.txt

# ... or with TM Transfer Frames
cargo run --release -p ccsds-viewer -- --mode tm-frames --frame-length 64 --fecf data/tm_frames.txt
cargo run --release -p ccsds-viewer -- --mode tm-frames --frame-length 48 --asm data/tm_frames_asm.txt
```

Then open <http://127.0.0.1:8080/> in the browser.

### Command line options

```text
Usage: ccsds-viewer [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input file with whitespace separated hex bytes ('#' starts a comment)

Options:
  -m, --mode <MODE>               Kind of data in the input file [default: packets]
                                  [possible values: packets, tm-frames]
  -l, --frame-length <OCTETS>     TM frames: total length of every Transfer Frame in
                                  octets (without Attached Sync Marker). Required with
                                  `--mode tm-frames`
      --fecf                      TM frames: every frame ends with a 2 octet Frame
                                  Error Control Field
      --ignore-crc                TM frames: show frames with a wrong FECF instead of
                                  treating them as invalid
      --asm[=<HEX>]               TM frames: every frame is preceded by an Attached
                                  Sync Marker. Without a value the standard marker
                                  1acffc1d is used
  -p, --port <PORT>          TCP port of the web server [default: 8080]
  -b, --bind <BIND>          Address the web server binds to [default: 127.0.0.1]
      --web-root <WEB_ROOT>  Directory containing index.html, style.css and the
                             WebAssembly package (pkg/) built with wasm-pack
      --dump                 Only print the stream to the console and exit
                             without starting the web server
  -h, --help                 Print help
  -V, --version              Print version
```

`--web-root` defaults to the `web/` directory of this workspace, so the
binary works out of the box when started from the source tree. When you
install or copy the binary elsewhere, pass `--web-root` explicitly.

Example console output:

```text
$ cargo run -q -p ccsds-viewer -- --dump data/example.txt
example.txt: 7 valid packet(s)
  @0      TM Space Packet APID=47    header: 08 2f c0 01 00 0f  data: 20 03 19 00 01 00 00 12 34 56 01 a4 0b b8 7f 00
  @22     TM Space Packet APID=47    header: 08 2f c0 02 00 03  data: de ad be ef
  ...
  first invalid item at byte offset 103: Packet Data Length announces 20 data byte(s), only 5 available

$ cargo run -q -p ccsds-viewer -- --dump -m tm-frames -l 64 --fecf data/tm_frames.txt
tm_frames.txt: 6 valid TM frame(s)
  @0      TM Transfer Frame SCID=42 VCID=1    header: 02 a3 00 00 18 00  data: 52 octets  trailer: 01 04 00 07 ea d0
  ...
  first invalid item at byte offset 384: Frame Error Control Field 0x6e16 does not match computed CRC 0xfca4
```

The frame options are only accepted together with `--mode tm-frames`.

## Input file format

- Each byte is written as one or two hexadecimal digits (`08`, `2f`, `C0`).
- Bytes are separated by whitespace (spaces, tabs, line breaks).
- Packets (or frames, optionally with ASM) simply follow each other, there
  is no separator between them.
- Everything from `#` to the end of a line is a comment.

```text
# TM, APID=47
08 2f c0 02 00 03 de ad be ef
# TC, APID=100
18 64 c0 05 00 07 21 11 01 00 2a 00 00 01
```

If the file contains a token that is not a valid hex byte, the byte stream
ends at that token; the packet affected by it is reported as invalid.

## HTTP interface

| Path            | Content                                    |
|-----------------|--------------------------------------------|
| `/`             | `web/index.html`                           |
| `/api/stream`   | the parsed stream (packets or TM frames) as JSON |
| `/<file>`       | static files from the web root             |

## Tests

```sh
cargo test
```

`cargo test` covers the packet and frame parsers, header decoding, the
FECF CRC, the packet extraction from frames, hex formatting, the command line option handling and the static
file path handling of the server. The WebAssembly crate is not part
of the default workspace members; check it with
`cargo check -p ccsds-web --target wasm32-unknown-unknown`.

## License

MIT OR Apache-2.0
