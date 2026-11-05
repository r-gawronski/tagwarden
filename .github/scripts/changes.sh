#!/usr/bin/env bash
# Writes code=false to $GITHUB_OUTPUT only when every changed file is docs-only.
# Any error, empty diff, tag or non-PR/push event means code=true.
# Env: EVENT, BASE, HEAD, REF_TYPE. Keep the pattern in sync with CONTRIBUTING.md.
set -u
docs='^(.*\.md|docs/.*|LICENSE|\.github/(CODEOWNERS|pull_request_template\.md|release\.yml|ISSUE_TEMPLATE/.*))$'
code=true
case "${EVENT:-}" in
  pull_request) range="${BASE:-}...${HEAD:-}" ;;
  push) range="${BASE:-}..${HEAD:-}" ;;
  *) range="" ;;
esac
if [ -n "$range" ] && [ "${REF_TYPE:-}" != tag ] && ! [[ "${BASE:-}" =~ ^0*$ ]]; then
  if files=$(git diff --no-renames --name-only "$range") && [ -n "$files" ]; then
    grep -qvE "$docs" <<<"$files"
    [ $? -eq 1 ] && code=false
    # test/docs applies the examples in docs/features.md.
    grep -qx docs/features.md <<<"$files" && code=true
  fi
fi
echo "docs-only check: code=$code"
echo "code=$code" >> "$GITHUB_OUTPUT"
