# CCSDS Space Packet, TM & TC Frame Viewer - User Guide

The viewer reads a text file with hex bytes containing CCSDS Space Packets,
CCSDS TM Transfer Frames or CCSDS TC Transfer Frames and shows them in the
web browser. Nothing has to be installed: the tool brings its own small web
server, and the browser needs no internet access.

## Contents of this package

```text
ccsds-viewer        the tool (command line application and web server)
web/                web interface, must stay next to the tool
examples/           example input files
USAGE.md            this guide
```

## Quick start

Open a terminal in the directory of this package and start the tool with one
of the example files:

```sh
./ccsds-viewer --web-root ./web examples/example.txt
```

The tool prints a short summary and the address of the web interface:

```text
example.txt: 7 valid packet(s)
  first invalid item at byte offset 103: Packet Data Length announces 20 data byte(s), only 5 available
Web interface: http://127.0.0.1:8080/  (Ctrl+C to stop)
```

Open <http://127.0.0.1:8080/> in the browser. The tool keeps running until
it is stopped with `Ctrl+C`. To look at another file, stop it and start it
again with the other file.

`--web-root ./web` tells the tool where the web interface is and is always
required. When the tool is started from another directory, give the path of
the `web` directory of this package instead of `./web`.

## Kinds of input

The kind of data in the file is selected with `--mode`.

### Space Packets (default)

```sh
./ccsds-viewer --web-root ./web examples/example.txt
```

### TM Transfer Frames

The frame length is not contained in a TM frame and must be given.

```sh
./ccsds-viewer --web-root ./web --mode tm-frames --frame-length 64 --fecf examples/tm_frames.txt
./ccsds-viewer --web-root ./web --mode tm-frames --frame-length 48 --asm examples/tm_frames_asm.txt
./ccsds-viewer --web-root ./web --mode tm-frames --frame-length 96 --fecf --sdls-header 6 --sdls-trailer 16 examples/tm_frames_sdls.txt
./ccsds-viewer --web-root ./web --mode tm-frames --frame-length 2048 --fecf examples/tm_frames_max.txt
```

### TC Transfer Frames

```sh
./ccsds-viewer --web-root ./web --mode tc-frames --segment-header --fecf examples/tc_frames.txt
./ccsds-viewer --web-root ./web --mode tc-frames --fecf --sdls-header 6 --sdls-trailer 16 examples/tc_frames_sdls.txt
./ccsds-viewer --web-root ./web --mode tc-frames --segment-header --fecf examples/tc_frames_max.txt
```

The file must contain the plain Transfer Frames; CLTUs are not decoded.

## Options

Several parts of a frame are not announced in the frame itself. Whether
they are present has to be told to the tool:

| Option | For | Meaning |
|--------|-----|---------|
| `-m`, `--mode <MODE>` | all | `packets` (default), `tm-frames` or `tc-frames` |
| `-l`, `--frame-length <OCTETS>` | TM | length of every frame in octets, without sync marker (required) |
| `--asm` or `--asm=<HEX>` | TM | every frame is preceded by an Attached Sync Marker (default `1acffc1d`) |
| `--segment-header` | TC | frames carrying data start their data field with a Segment Header |
| `--fecf` | TM, TC | every frame ends with a Frame Error Control Field (CRC) |
| `--ignore-crc` | TM, TC | show frames with a wrong CRC instead of stopping at them |
| `--sdls-header <OCTETS>` | TM, TC | every frame has a Security Header of this length (at least 2) |
| `--sdls-trailer <OCTETS>` | TM, TC | every frame has a Security Trailer of this length |
| `--sdls-encrypted` | TM, TC | the data field is encrypted: do not search it for Space Packets |
| `-p`, `--port <PORT>` | all | port of the web interface (default 8080) |
| `-b`, `--bind <ADDRESS>` | all | address of the web interface (default 127.0.0.1, this computer only) |
| `--web-root <DIRECTORY>` | all | the `web` directory of this package (required) |
| `--dump` | all | print the content to the terminal and exit, without web interface |
| `-h`, `--help` | all | show all options |

The Secondary Header and the Operational Control Field of a TM frame are
announced by flags in the frame and are found automatically.

The tool has no keys: the Security Header and the Security Trailer are
shown as hex bytes, nothing is verified or decrypted.

## The web interface

- The **overview** shows all packets or frames next to each other, each with
  its parts as hex bytes.
- **Moving the mouse** over a packet or frame shows its **detail view** with
  all header fields. Values are shown in decimal and, where useful, in hex.
- A **click** pins the detail view. A click outside of it or the Escape key
  closes it.
- For frames, the pinned detail view marks the Space Packets inside the
  *Transfer Frame Data Field* in alternating colours. A click on a packet
  opens the page with the **Space Packets that start in this frame**. The
  heading of that page leads back to the frame; the back button of the
  browser works as well.
- The first part of the file that is not a valid packet or frame is shown
  as a **red box** with the reason. The data after it is not displayed.

## Input file format

- Each byte is written as one or two hexadecimal digits (`08`, `2f`, `C0`).
- Bytes are separated by spaces, tabs or line breaks.
- Packets or frames simply follow each other without separator.
- Everything from `#` to the end of a line is a comment.

```text
# TM, APID=47
08 2f c0 02 00 03 de ad be ef
# TC, APID=100
18 64 c0 05 00 07 21 11 01 00 2a 00 00 01
```

## Problems

| Message or symptom | Cause and remedy |
|--------------------|------------------|
| `web root '...' not found` | `--web-root` is missing or points to the wrong directory. Give the path of the `web` directory of this package. |
| `web server failed: ... Address already in use` | Another program (or another instance of the tool) uses the port. Choose another one with `--port`, e.g. `--port 8081`. |
| `--frame-length is required with --mode tm-frames` | Add `--frame-length <OCTETS>`. |
| The page stays at "Loading data..." | The `web/pkg` directory is missing or incomplete. Unpack the package again. |
| Red box right at the beginning | The options do not match the file (wrong mode or frame length, missing `--fecf`, `--asm`, `--segment-header` or `--sdls-header`). |
| The tool does not start (`GLIBC_... not found`) | The package was built for a newer Linux system. Ask for a package built for your system. |
