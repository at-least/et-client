# Linux test environment for et: the Rust workspace plus the upstream C++
# binaries (et 7.0.0, protocol v6) for the interop suite. Used by
# scripts/docker-test.sh and doubles as the client library's Linux build
# validation.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential file gnupg \
        software-properties-common \
 && add-apt-repository -y ppa:jgmath2000/et \
 && apt-get update \
 && apt-get install -y --no-install-recommends et \
 && rm -rf /var/lib/apt/lists/* \
 && etserver --version

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable --component clippy
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /work
