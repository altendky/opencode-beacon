#!/usr/bin/env bash
set -euo pipefail

toolchain="$(awk -F '"' '/^channel =/ { print $2 }' rust-toolchain.toml)"
exec rustup run "$toolchain" cargo "$@"
