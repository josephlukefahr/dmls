#!/usr/bin/env bash

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
binary="$repo_root/target/debug/dmls"

participants=(alice bob charlie)

echo "Generating key packages for (${participants[@]})."

for p1 in "${participants[@]}"; do
  outName="for_${p1}.mlskp"
  echo "Generating key packages for ${p1}"
  for p2 in "${participants[@]}"; do
    if [ $p1 != $p2 ]; then
      state="${p2}.json"
      $binary use-state $state gen-kp >> $outName
    fi
  done
done

echo "Key package generation completed."
