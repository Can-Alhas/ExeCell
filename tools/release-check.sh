#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${1:-"$root/build-release-check"}
sbom=${2:-"$build_dir/sbom.jsonl"}

cmake -S "$root" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build "$build_dir" --parallel
ctest --test-dir "$build_dir" --output-on-failure
git -C "$root" diff --check

umask 077
{
    printf '%s\n' '{"schema":"execell-sbom-1","components":['
    first=1
    for file in "$build_dir/execell"; do
        [ -f "$file" ] || continue
        hash=$(sha256sum "$file" | cut -d ' ' -f 1)
        size=$(wc -c < "$file" | tr -d ' ')
        if [ "$first" -eq 0 ]; then printf ',\n'; fi
        first=0
        printf '{"path":"%s","sha256":"%s","size":%s}' \
            "$(basename "$file")" "$hash" "$size"
    done
    printf '%s\n' ']}'
} > "$sbom"

printf 'release verification passed\nSBOM: %s\n' "$sbom"
