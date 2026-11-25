ARG FACTORY_BASE_IMAGE
FROM ${FACTORY_BASE_IMAGE} AS base

ARG TARGETARCH
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

COPY ci/pins.env /opt/factory/pins.env
COPY rust-toolchain.toml /opt/factory/rust-toolchain.toml

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip xz-utils zstd; \
    rm -rf /var/lib/apt/lists/*; \
    git config --system --add safe.directory '*'

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    case "$TARGETARCH" in \
      amd64) asset=bun-linux-x64; sum="$FACTORY_BUN_SHA256_AMD64" ;; \
      arm64) asset=bun-linux-aarch64; sum="$FACTORY_BUN_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/${asset}.zip"; \
    echo "${sum}  /tmp/bun.zip" | sha256sum --check --strict; \
    unzip -q /tmp/bun.zip -d /tmp/bun; \
    install -m 0755 "/tmp/bun/${asset}/bun" /usr/local/bin/bun; \
    rm -rf /tmp/bun /tmp/bun.zip; \
    bun --version

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    git clone --quiet https://github.com/bendlang/bend /opt/bend; \
    git -C /opt/bend checkout --quiet "$BEND_COMMIT"; \
    [ "$(git -C /opt/bend rev-parse HEAD)" = "$BEND_COMMIT" ] || { echo "bend is not at BEND_COMMIT" >&2; exit 1; }; \
    printf '#!/bin/sh\nexec bun /opt/bend/bend2/main.ts "$@"\n' > /usr/local/bin/bend; \
    chmod +x /usr/local/bin/bend

WORKDIR /work

FROM base AS proofs
ARG TARGETARCH

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    case "$TARGETARCH" in \
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

CMD ["scripts/verdict.sh"]

FROM base AS check
ARG TARGETARCH

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    apt-get update; \
    apt-get install -y --no-install-recommends gcc libc6-dev "openjdk-${JAVA_VERSION}-jre-headless"; \
    rm -rf /var/lib/apt/lists/*

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    case "$TARGETARCH" in \
      amd64) arch=x64; sum="$FACTORY_NODE_SHA256_AMD64" ;; \
      arm64) arch=arm64; sum="$FACTORY_NODE_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${FACTORY_NODE_VERSION}/node-v${FACTORY_NODE_VERSION}-linux-${arch}.tar.xz"; \
    echo "${sum}  /tmp/node.tar.xz" | sha256sum --check --strict; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm /tmp/node.tar.xz; \
    [[ "$FACTORY_NODE_VERSION" == "$NODE_VERSION".* ]] || { echo "FACTORY_NODE_VERSION is not Node $NODE_VERSION" >&2; exit 1; }; \
    node --version

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    mkdir -p /opt/tla; \
    curl -fsSL -o "$TLA2TOOLS" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"; \
    echo "${TLA_SHA256}  ${TLA2TOOLS}" | sha256sum --check --strict; \
    java -version

RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum="$FACTORY_RUSTUP_INIT_SHA256_AMD64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="$FACTORY_RUSTUP_INIT_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${FACTORY_RUSTUP_VERSION}/${triple}/rustup-init"; \
    echo "${sum}  /tmp/rustup-init" | sha256sum --check --strict; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none; \
    rm /tmp/rustup-init; \
    channel="$(sed -n 's/^channel = "\(.*\)"/\1/p' /opt/factory/rust-toolchain.toml)"; \
    [ -n "$channel" ] || { echo "rust-toolchain.toml has no channel" >&2; exit 1; }; \
    rustup toolchain install "$channel" --profile minimal -c clippy -c rustfmt -t wasm32-unknown-unknown; \
    rustup default "$channel"; \
    cargo --version

COPY .python-version /opt/factory/.python-version
RUN source <(grep -E '^[A-Z0-9_]+=' /opt/factory/pins.env); \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; sum="$FACTORY_UV_SHA256_AMD64" ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum="$FACTORY_UV_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/uv.tar.gz "https://github.com/astral-sh/uv/releases/download/${FACTORY_UV_VERSION}/uv-${triple}.tar.gz"; \
    echo "${sum}  /tmp/uv.tar.gz" | sha256sum --check --strict; \
    tar -xzf /tmp/uv.tar.gz -C /usr/local/bin --strip-components=1 "uv-${triple}/uv"; \
    rm /tmp/uv.tar.gz; \
    UV_PYTHON_DOWNLOADS=manual uv python install "$(cat /opt/factory/.python-version)"; \
    chmod -R a+rX /opt/python; \
    uv run --no-project python --version

COPY Cargo.toml Cargo.lock /tmp/prefetch/
COPY .cargo /tmp/prefetch/.cargo
COPY crates /tmp/prefetch/crates
RUN cd /tmp/prefetch; \
    mkdir -p crates/containment-kernel/src crates/containment-wasm/src crates/containment-host/src; \
    touch crates/containment-kernel/src/lib.rs crates/containment-wasm/src/lib.rs crates/containment-host/src/main.rs; \
    cargo fetch --locked; \
    rm -rf /tmp/prefetch

CMD ["scripts/check.sh"]

FROM check AS dev
COPY --from=proofs /opt/lean /opt/lean
RUN apt-get update; \
    apt-get install -y --no-install-recommends gh less openssh-client; \
    rm -rf /var/lib/apt/lists/*; \
    lean --version
CMD ["bash"]
