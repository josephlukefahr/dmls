#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"
RUST_LOG=warn

participants=(alice bob charlie)

echo "Generating encrypted messages for (${participants[@]})."

for p1 in "${participants[@]}"; do
  state="${p1}.json"
  outName="${p1}.mlsmsg"
  echo "Using ${p1} to encrypt messages"
  echo "This is a test message from ${p1}." | $binary use-state $state encrypt >> $outName
  cat lipsum | $binary use-state $state encrypt >> $outName
  # cat lipsum | base64 --wrap=0 | $binary use-state $state encrypt >> $outName
done

echo "Welcome messages saved."
