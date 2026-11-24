#!/usr/bin/env bash
# Compatibility launcher for existing desktop entries.
exec "$(dirname "$(realpath "$0")")/namik-app.sh" "$@"
