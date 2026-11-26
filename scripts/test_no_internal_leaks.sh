#!/bin/sh
set -eu

root=$(git rev-parse --show-toplevel)
gate="$root/scripts/gate_no_internal_leaks.sh"
mkdir -p "$root/.artifacts/tests"
fixture=$(mktemp -d "$root/.artifacts/tests/leaks.XXXXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
cd "$fixture"
git init -q
cp "$root/AGENTS.md" .
git add AGENTS.md

home_path=$(printf '/%s/%s/include' home fixture-user)
printf '%s\n' "$home_path" > flags.rsp
sh "$gate"  # The path is untracked and the public DevKit reference is tracked.

git add flags.rsp
for flag in '' -I -L; do
    printf '%s%s\n' "$flag" "$home_path" > flags.rsp
    if sh "$gate" > result 2>&1; then
        echo "Gate accepted a tracked home path with prefix '$flag'" >&2
        exit 1
    fi
    grep -Fxq flags.rsp result || { cat result >&2; exit 1; }
done
