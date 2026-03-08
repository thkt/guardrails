#!/usr/bin/env bash
set -euo pipefail

TOOL="$1"
HOOK_INPUT=$(cat)

if command -v "$TOOL" &>/dev/null; then
  echo "$HOOK_INPUT" | "$TOOL"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  echo "${TOOL} not installed. Run: ${SCRIPT_DIR}/install.sh" >&2
  exit 0
fi
