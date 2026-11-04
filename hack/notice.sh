#!/usr/bin/env bash
# Regenerates NOTICE: the project notice plus the NOTICE files of every Go
# module compiled into the linux manager binary (Apache-2.0 section 4(d)).
set -euo pipefail
cd "$(dirname "$0")/.."

modcache=$(go env GOMODCACHE)
{
  cat <<'HDR'
Tagwarden
Copyright 2026 The Tagwarden Authors.

This product includes software developed by The Tagwarden Authors
(https://github.com/r-gawronski/tagwarden).

The binaries and container images also include the third-party Go modules
below. Their NOTICE files are reproduced as required by their licenses.
HDR
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps \
    -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}' ./cmd/ |
    sort -u |
    while read -r path dir; do
      for f in NOTICE NOTICE.txt NOTICE.md; do
        [ -f "$dir/$f" ] || continue
        printf '\n================================================================\n%s\n================================================================\n\n' "$path"
        cat "$dir/$f"
        break
      done
    done
} > NOTICE
