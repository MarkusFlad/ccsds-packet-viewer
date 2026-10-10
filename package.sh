#!/usr/bin/env bash
# Builds the delivery package of the viewer:
#
#   dist/ccsds-viewer-<version>-<platform>.tar.gz
#
# The archive contains the executable, the web assets, the example files and
# the user guide (USAGE.md). See "Delivery" in README.md.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Running the tests"
cargo test --workspace

echo "==> Building the WebAssembly frontend"
wasm-pack build crates/ccsds-web --target web --release --out-dir ../../web/pkg --no-typescript

echo "==> Building the viewer"
cargo build --release -p ccsds-viewer

version=$(target/release/ccsds-viewer --version | cut -d' ' -f2)
# Operating system and processor architecture, e.g. "linux-x86_64".
platform="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
name="ccsds-viewer-$version"
stage="target/package/$name"
archive="dist/$name-$platform.tar.gz"

echo "==> Collecting the files"
rm -rf "$stage"
mkdir -p "$stage/web/pkg" "$stage/examples" dist
cp target/release/ccsds-viewer "$stage/"
cp web/index.html web/style.css "$stage/web/"
cp web/pkg/ccsds_web.js web/pkg/ccsds_web_bg.wasm "$stage/web/pkg/"
# The "Run:" comments of the examples refer to the source tree.
for file in data/*.txt; do
    sed -e '/^# Run: /s|ccsds-viewer |./ccsds-viewer --web-root ./web |' \
        -e '/^# Run: /s| data/| examples/|' "$file" > "$stage/examples/$(basename "$file")"
done
cp USAGE.md "$stage/"

echo "==> Writing $archive"
tar -czf "$archive" -C target/package "$name"
tar -tzf "$archive"
