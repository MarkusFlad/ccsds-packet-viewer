#!/usr/bin/env bash
# Builds the delivery package of the viewer:
#
#   dist/ccsds-viewer-<version>-<platform>.tar.gz
#
# The archive contains the executable, the web assets, the example files and
# the user guide (USAGE.md) and the license texts. See "Delivery" in README.md.
#
# The executable is built for the musl target and therefore linked
# statically: it does not depend on the C library of the target computer.
set -euo pipefail

cd "$(dirname "$0")"

arch=$(uname -m)
target="$arch-unknown-linux-musl"
if ! rustup target list --installed | grep -qx "$target"; then
    echo "error: Rust target $target is not installed." >&2
    echo "       Install it with: rustup target add $target" >&2
    exit 1
fi

echo "==> Running the tests"
cargo test --workspace

echo "==> Building the WebAssembly frontend"
wasm-pack build crates/ccsds-web --target web --release --out-dir ../../web/pkg --no-typescript

echo "==> Building the viewer"
cargo build --release -p ccsds-viewer --target "$target"
binary="target/$target/release/ccsds-viewer"

version=$("$binary" --version | cut -d' ' -f2)
name="ccsds-viewer-$version"
stage="target/package/$name"
archive="dist/$name-linux-$arch.tar.gz"

echo "==> Collecting the files"
rm -rf "$stage"
mkdir -p "$stage/web/pkg" "$stage/examples" dist
cp "$binary" "$stage/"
cp web/index.html web/style.css "$stage/web/"
cp web/pkg/ccsds_web.js web/pkg/ccsds_web_bg.wasm "$stage/web/pkg/"
# The "Run:" comments of the examples refer to the source tree.
for file in data/*.txt; do
    sed -e '/^# Run: /s|ccsds-viewer |./ccsds-viewer --web-root ./web |' \
        -e '/^# Run: /s| data/| examples/|' "$file" > "$stage/examples/$(basename "$file")"
done
cp USAGE.md LICENSE-MIT LICENSE-APACHE "$stage/"

echo "==> Writing $archive"
tar -czf "$archive" -C target/package "$name"
tar -tzf "$archive"
