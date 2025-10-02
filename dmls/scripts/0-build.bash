#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"

echo "Building dmls (debug)..."
pushd "$repo_root" > /dev/null
cargo build
popd > /dev/null

echo "Build finished. Binary should be at $binary."
