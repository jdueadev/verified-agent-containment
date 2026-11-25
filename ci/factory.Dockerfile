# Every tool is fetched in its own stage, from only the pins it needs, and the
# images at the bottom copy the results in. BuildKit builds the fetch stages in
# parallel, and changing one pin rebuilds one stage. scripts/factory.sh passes
# each line of ci/pins.env as a build argument.
ARG FACTORY_BASE_IMAGE
FROM ${FACTORY_BASE_IMAGE} AS os

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

LABEL org.opencontainers.image.source="https://github.com/vac-dev-team/verified-agent-containment"
LABEL org.opencontainers.image.description="Pinned toolchain for verified-agent-containment checks"

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    TLA2TOOLS=/opt/tla/tla2tools.jar \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/tmp/vac-venv \
    PATH=/opt/cargo/bin:/opt/lean/bin:/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl git unzip xz-utils zstd; \
    rm -rf /var/lib/apt/lists/*; \
    git config --system --add safe.directory '*'

WORKDIR /work


FROM os AS get-bun
ARG TARGETARCH
ARG BUN_VERSION
ARG FACTORY_BUN_SHA256_AMD64
ARG FACTORY_BUN_SHA256_ARM64
RUN case "$TARGETARCH" in \
      amd64) asset=bun-linux-x64; sum="$FACTORY_BUN_SHA256_AMD64" ;; \
      arm64) asset=bun-linux-aarch64; sum="$FACTORY_BUN_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/${asset}.zip"; \
    echo "${sum}  /tmp/bun.zip" | sha256sum --check --strict; \
    unzip -q /tmp/bun.zip -d /tmp/bun; \
    install -D -m 0755 "/tmp/bun/${asset}/bun" /out/bun; \
    /out/bun --version


FROM os AS get-bend
ARG BEND_COMMIT
RUN git clone --quiet https://github.com/bendlang/bend /opt/bend; \
    git -C /opt/bend checkout --quiet "$BEND_COMMIT"; \
    [ "$(git -C /opt/bend rev-parse HEAD)" = "$BEND_COMMIT" ] || { echo "bend is not at BEND_COMMIT" >&2; exit 1; }; \
    mkdir /out; \
    printf '#!/bin/sh\nexec bun /opt/bend/bend2/main.ts "$@"\n' > /out/bend; \
    chmod +x /out/bend


FROM os AS get-lean
ARG TARGETARCH
ARG LEAN_VERSION
ARG FACTORY_LEAN_SHA256_AMD64
ARG FACTORY_LEAN_SHA256_ARM64
RUN case "$TARGETARCH" in \
      amd64) asset="lean-${LEAN_VERSION}-linux"; sum="$FACTORY_LEAN_SHA256_AMD64" ;; \
      arm64) asset="lean-${LEAN_VERSION}-linux_aarch64"; sum="$FACTORY_LEAN_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/lean.tar.zst "https://github.com/leanprover/lean4/releases/download/v${LEAN_VERSION}/${asset}.tar.zst"; \
    echo "${sum}  /tmp/lean.tar.zst" | sha256sum --check --strict; \
    mkdir -p /opt/lean; \
    tar --zstd -xf /tmp/lean.tar.zst -C /opt/lean --strip-components=1; \
    rm /tmp/lean.tar.zst; \
    lean --version


FROM os AS get-node
ARG TARGETARCH
ARG NODE_VERSION
ARG FACTORY_NODE_VERSION
ARG FACTORY_NODE_SHA256_AMD64
ARG FACTORY_NODE_SHA256_ARM64
RUN case "$TARGETARCH" in \
      amd64) arch=x64; sum="$FACTORY_NODE_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$FACTORY_NODE_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    [[ "$FACTORY_NODE_VERSION" == "$NODE_VERSION".* ]] || { echo "FACTORY_NODE_VERSION is not Node $NODE_VERSION" >&2; exit 1; }; \
    curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${FACTORY_NODE_VERSION}/node-v${FACTORY_NODE_VERSION}-linux-${arch}.tar.xz"; \
    echo "${sum}  /tmp/node.tar.xz" | sha256sum --check --strict; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm /tmp/node.tar.xz; \
    node --version


FROM os AS get-tla
ARG TLA_VERSION
ARG TLA_SHA256
RUN mkdir -p /opt/tla; \
    curl -fsSL -o "$TLA2TOOLS" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"; \
    echo "${TLA_SHA256}  ${TLA2TOOLS}" | sha256sum --check --strict


FROM os AS get-python
ARG TARGETARCH
ARG FACTORY_UV_VERSION
ARG FACTORY_UV_SHA256_AMD64
ARG FACTORY_UV_SHA256_ARM64
COPY .python-version /tmp/.python-version
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum="$FACTORY_UV_SHA256_AMD64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="$FACTORY_UV_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${FACTORY_UV_VERSION}/uv-${triple}.tar.gz"; \
    echo "${sum}  /tmp/uv.tar.gz" | sha256sum --check --strict; \
    mkdir /out; \
    tar -xzf /tmp/uv.tar.gz -C /out --strip-components=1 "uv-${triple}/uv"; \
    UV_PYTHON_DOWNLOADS=manual /out/uv python install "$(cat /tmp/.python-version)"; \
    chmod -R a+rX /opt/python; \
    /out/uv run --no-project python --version


FROM os AS get-rust
ARG TARGETARCH
ARG FACTORY_RUSTUP_VERSION
ARG FACTORY_RUSTUP_INIT_SHA256_AMD64
ARG FACTORY_RUSTUP_INIT_SHA256_ARM64
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum="$FACTORY_RUSTUP_INIT_SHA256_AMD64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="$FACTORY_RUSTUP_INIT_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${FACTORY_RUSTUP_VERSION}/${triple}/rustup-init"; \
    echo "${sum}  /tmp/rustup-init" | sha256sum --check --strict; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none; \
    rm /tmp/rustup-init; \
    channel="$(sed -n 's/^channel = "\(.*\)"/\1/p' /tmp/rust-toolchain.toml)"; \
    [ -n "$channel" ] || { echo "rust-toolchain.toml has no channel" >&2; exit 1; }; \
    rustup toolchain install "$channel" --profile minimal -c clippy -c rustfmt -t wasm32-unknown-unknown; \
    rustup default "$channel"; \
    cargo --version


# Only the manifests and the lock file are in the build context, so editing Rust
# source leaves this stage cached. The empty files are the targets the manifests name.
FROM get-rust AS get-crates
COPY Cargo.toml Cargo.lock /tmp/prefetch/
COPY .cargo /tmp/prefetch/.cargo
COPY crates /tmp/prefetch/crates
RUN cd /tmp/prefetch; \
    mkdir -p crates/containment-kernel/src crates/containment-wasm/src crates/containment-host/src; \
    touch crates/containment-kernel/src/lib.rs crates/containment-wasm/src/lib.rs crates/containment-host/src/main.rs; \
    cargo fetch --locked; \
    mkdir /out; \
    mv /opt/cargo/registry /out/registry


# Kani comes in two parts. The cargo-kani front end is built from crates.io with
# the lock file it was published with; it needs a linker, so this stage has gcc.
# The release bundle (CBMC, kani-compiler, kani-driver) is checked against our
# sum, and setup unpacks it into KANI_HOME and installs through rustup the
# nightly toolchain kani-compiler is linked against. The toolchain leaves in
# /out/toolchains so the kani image copies it without a second stable toolchain.
FROM get-rust AS get-kani
ARG TARGETARCH
ARG KANI_VERSION
ARG FACTORY_KANI_SHA256_AMD64
ARG FACTORY_KANI_SHA256_ARM64
ENV KANI_HOME=/opt/kani
RUN apt-get update; \
    apt-get install -y --no-install-recommends gcc libc6-dev; \
    rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum="$FACTORY_KANI_SHA256_AMD64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="$FACTORY_KANI_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/kani.tar.gz "https://github.com/model-checking/kani/releases/download/kani-${KANI_VERSION}/kani-${KANI_VERSION}-${triple}.tar.gz"; \
    echo "${sum}  /tmp/kani.tar.gz" | sha256sum --check --strict; \
    cargo install --locked --root /out kani-verifier --version "$KANI_VERSION"; \
    rustup set auto-self-update disable; \
    /out/bin/cargo-kani setup --use-local-bundle /tmp/kani.tar.gz; \
    rm /tmp/kani.tar.gz; \
    kani_dir="$KANI_HOME/kani-$KANI_VERSION"; \
    chown -R 0:0 "$kani_dir"; \
    toolchain="$(cat "$kani_dir/rust-toolchain-version")"; \
    [ "$(readlink "$kani_dir/toolchain")" = "$RUSTUP_HOME/toolchains/$toolchain" ] || { echo "kani: the toolchain link is not $RUSTUP_HOME/toolchains/$toolchain" >&2; exit 1; }; \
    [ "$("$kani_dir/toolchain/bin/rustc" --version)" = "$(cat "$kani_dir/rustc-version")" ] || { echo "kani: the nightly rustup installed is not the rustc the bundle was built with" >&2; exit 1; }; \
    PATH="/out/bin:$PATH" cargo kani --version; \
    mkdir /out/toolchains; \
    mv "$RUSTUP_HOME/toolchains/$toolchain" /out/toolchains/


FROM os AS proofs
COPY --from=get-lean /opt/lean /opt/lean
COPY --from=get-bend /opt/bend /opt/bend
COPY --from=get-bend /out/bend /usr/local/bin/bend
COPY --from=get-bun /out/bun /usr/local/bin/bun
CMD ["scripts/verdict.sh"]


# Ordered from what changes least to what changes most, so a change near the
# bottom keeps the layers above it.
FROM os AS check
ARG JAVA_VERSION
RUN apt-get update; \
    apt-get install -y --no-install-recommends gcc libc6-dev "openjdk-${JAVA_VERSION}-jre-headless"; \
    rm -rf /var/lib/apt/lists/*; \
    java -version
COPY --from=get-tla /opt/tla /opt/tla
COPY --from=get-node /opt/node /opt/node
COPY --from=get-python /opt/python /opt/python
COPY --from=get-python /out/uv /usr/local/bin/uv
COPY --from=get-bend /opt/bend /opt/bend
COPY --from=get-bend /out/bend /usr/local/bin/bend
COPY --from=get-bun /out/bun /usr/local/bin/bun
COPY --from=get-rust /opt/rustup /opt/rustup
COPY --from=get-rust /opt/cargo /opt/cargo
COPY --from=get-crates /out/registry /opt/cargo/registry
CMD ["scripts/check.sh"]


# Its own image, not part of check: the bundle and the nightly toolchain add 1.1 GB
# (measured unpacked on amd64) that scripts/check.sh never reads. It shares every
# layer of check, so a machine that has check fetches only that.
FROM check AS kani
ENV KANI_HOME=/opt/kani
COPY --from=get-kani /out/toolchains/ /opt/rustup/toolchains/
COPY --from=get-kani /opt/kani /opt/kani
COPY --from=get-kani /out/bin/cargo-kani /out/bin/kani /usr/local/bin/
CMD ["scripts/kani.sh"]


FROM check AS dev
RUN apt-get update; \
    apt-get install -y --no-install-recommends gh less openssh-client; \
    rm -rf /var/lib/apt/lists/*
COPY --from=get-lean /opt/lean /opt/lean
CMD ["bash"]
