#!/usr/bin/env bash
# Runs the full test suite (including the C++ interop tests) inside a Linux
# container: `scripts/docker-test.sh`. Also validates the Linux build of the
# client library and its tests.
#
# The repo is mounted read-write (cargo needs it) with a named volume caching
# the Linux target dir across runs. ET_CPP_PREFIX points the interop tests at
# the container's et install.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -q -t et-test -f Dockerfile . >/dev/null

docker run --rm \
    -v "$PWD:/work" \
    -v et-linux-target:/tmp/et-target \
    -w /work \
    -e CARGO_TARGET_DIR=/tmp/et-target \
    -e ET_CPP_PREFIX=/usr \
    et-test \
    bash -exc '
        cargo test --workspace
        cargo test -p et-client --test cpp_interop -- --ignored
        cargo clippy --workspace --all-targets -- -D warnings
    '
