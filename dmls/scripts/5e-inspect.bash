#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"

participants=(alice bob charlie)

echo "Inspecting messages for (${participants[@]})."

for p1 in "${participants[@]}"; do
  inName="from_${p1}.mlsmsg"
  echo "Inspecting messages from ${p1}"
  cat $inName | RUST_LOG=warn $binary inspect-messages
done

echo "Done."
