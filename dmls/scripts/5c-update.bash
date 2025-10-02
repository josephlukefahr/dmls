#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"
RUST_LOG=warn

participants=(alice bob charlie)

echo "Updating (${participants[@]})."

for p1 in "${participants[@]}"; do
  state="${p1}.json"
  outName="from_${p1}.mlsmsg"
  echo "Using ${p1} to update"
  $binary use-state $state update >> $outName
done

echo "Updates saved."
