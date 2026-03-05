#!/usr/bin/env bash
set -euo pipefail

cargo run -- --format json | sed -n '1,120p'
