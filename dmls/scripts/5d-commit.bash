#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"
RUST_LOG=warn

participants=(alice bob charlie)

echo "Committing cross-grou injects (${participants[@]})."

for p1 in "${participants[@]}"; do
  state="${p1}.json"
  outName="from_${p1}.mlsmsg"
  echo "Using ${p1} to commit cross-group injects"
  $binary use-state $state commit >> $outName
done

echo "Commits saved."
