#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"

echo "Generating state files for alice, bob, charlie"

$binary gen-state alice.json
$binary gen-state bob.json
$binary gen-state charlie.json

echo "States written: alice.json, bob.json, charlie.json"
