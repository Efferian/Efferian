#!/bin/sh
set -eu

printf '%s\n' 'Physical Rust lines by file, including comments and tests'
find apps packages -type f -name '*.rs' -exec wc -l {} +
