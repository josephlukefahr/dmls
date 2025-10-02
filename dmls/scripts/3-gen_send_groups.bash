#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"


participants=(alice bob charlie)

echo "Generating send groups for (${participants[@]})."

for p1 in "${participants[@]}"; do
  state="${p1}.json"
  inName="for_${p1}.mlskp"
  outName="from_${p1}.mlsmsg"
  echo "Generating welcome message for ${p1}"
  cat $inName | RUST_LOG=warn $binary use-state $state gen-send-group >> $outName
  rm $inName
done

echo "Welcome messages saved."
