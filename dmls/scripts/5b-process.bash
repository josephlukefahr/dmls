#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"

participants=(alice bob charlie)

echo "Processing messages for (${participants[@]})."

for p1 in "${participants[@]}"; do
  inName="from_${p1}.mlsmsg"
  for p2 in "${participants[@]}"; do
    if [ $p1 != $p2 ]; then
      state="${p2}.json"
      echo "Using ${p2} to process messages from ${p1}"
      cat $inName | RUST_LOG=warn $binary use-state $state process
    fi
  done
done

echo "Messages processed."
