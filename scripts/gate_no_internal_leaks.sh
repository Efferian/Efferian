#!/bin/sh
set -eu

root=$(git rev-parse --show-toplevel)
cd "$root"

# Match machine-specific home paths and private-key headers. Report paths only.
# Compiler response files can attach the path directly to a flag such as -I.
home='(^|file://|[^[:alnum:]_.~/])(-[[:alpha:]]+)?(/(home|Users|root)/[^/[:space:]]|[[:alpha:]]:[/\\]+Users[/\\]+[^/\\[:space:]])'
key='-{5}BEGIN ([[:upper:][:digit:]]+ )*PRIVATE KEY( BLOCK)?-{5}'
pattern="$home|$key"
if git --no-pager grep -IlE -e "$pattern" -- .; then
    echo 'Tracked text contains a local home path or private-key header.' >&2
    exit 1
else
    status=$?
    [ "$status" -eq 1 ] || exit "$status"
fi

# Git grep skips symbolic links. Inspect the tracked link itself without
# reading its destination, which may be outside the checkout.
git ls-files -z | xargs -0 sh -ec '
    pattern=$1
    shift
    for path do
        [ -L "$path" ] || continue
        target=$(readlink -- "$path")
        if printf "%s\n" "$target" | grep -Eq -e "$pattern"; then
            printf "Tracked link contains a local home path: %s\n" "$path" >&2
            exit 1
        fi
    done
' sh "$pattern"
