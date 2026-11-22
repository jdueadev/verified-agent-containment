# The container that runs scripts/check.sh (#55,
# docs/decisions/0006-check-container.md). Build and run it with
# scripts/check-in-container.sh, which passes every key of ci/pins.env as a
# --build-arg and builds from a context that holds only the files copied below.
#
# No version is written here. Every pin is an ARG with no default, a missing
# one is an error, and each must equal ci/pins.env as copied into the image.
# The Rust version comes from rust-toolchain.toml. Every download is checked
# against a pinned sha256 before it is used, except two that upstream signs:
# apt packages (Ubuntu's signed index, from a pinned snapshot) and the Rust
# toolchain (rustup checks each component against the channel manifest).
# The base image's index digest selects amd64; the pinned checksums are for
# x86_64 binaries only.
ARG CHECK_BASE_IMAGE
FROM ${CHECK_BASE_IMAGE}

ARG CHECK_BASE_IMAGE
ARG UBUNTU_SNAPSHOT
ARG PYTHON_VERSION
ARG BUN_VERSION
ARG BUN_SHA256
ARG NODE_VERSION
ARG NODE_SHA256
ARG JAVA_VERSION
ARG JRE_VERSION
ARG JRE_SHA256
ARG BEND_COMMIT
ARG TLA_VERSION
ARG TLA_SHA256
ARG RUSTUP_VERSION
ARG RUSTUP_INIT_SHA256

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Each build-arg must be set and must equal its line in ci/pins.env, so the
# image cannot carry a version the file does not state.
COPY ci/pins.env /opt/check/ci/pins.env
RUN same() { \
      local want; want="$(sed -n "s/^$1=//p" /opt/check/ci/pins.env)"; \
      if [ -z "$2" ] || [ "$2" != "$want" ]; then \
        echo "build-arg $1='$2' does not match ci/pins.env ('$want')" >&2; exit 1; \
      fi; \
    }; \
    same CHECK_BASE_IMAGE "$CHECK_BASE_IMAGE"; same UBUNTU_SNAPSHOT "$UBUNTU_SNAPSHOT"; \
    same PYTHON_VERSION "$PYTHON_VERSION"; same BUN_VERSION "$BUN_VERSION"; \
    same BUN_SHA256 "$BUN_SHA256"; same NODE_VERSION "$NODE_VERSION"; \
    same NODE_SHA256 "$NODE_SHA256"; same JAVA_VERSION "$JAVA_VERSION"; \
    same JRE_VERSION "$JRE_VERSION"; same JRE_SHA256 "$JRE_SHA256"; \
    same BEND_COMMIT "$BEND_COMMIT"; same TLA_VERSION "$TLA_VERSION"; \
    same TLA_SHA256 "$TLA_SHA256"; same RUSTUP_VERSION "$RUSTUP_VERSION"; \
    same RUSTUP_INIT_SHA256 "$RUSTUP_INIT_SHA256"; \
    [[ "$CHECK_BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "CHECK_BASE_IMAGE must be pinned by digest" >&2; exit 1; }; \
    [[ "$NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "NODE_VERSION must be an exact version" >&2; exit 1; }; \
    [[ "$JRE_VERSION" == "$JAVA_VERSION".* ]] || { echo "JRE_VERSION $JRE_VERSION is not Java $JAVA_VERSION" >&2; exit 1; }; \
    for sum in "$BUN_SHA256" "$NODE_SHA256" "$JRE_SHA256" "$TLA_SHA256" "$RUSTUP_INIT_SHA256"; do \
      [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || { echo "not a sha256: $sum" >&2; exit 1; }; \
    done

# Ubuntu packages from a fixed snapshot of the archive, so a rebuild gets the
# same python3, git and gcc. The base image has no CA certificates yet and the
# snapshot service redirects http to https, so these apt runs skip TLS peer
# checks. apt's trust is the archive's signed InRelease and the hashes it
# lists, as with the image's default http:// sources; TLS adds none.
RUN src=/etc/apt/sources.list.d/ubuntu.sources; \
    [ "$(ls -A /etc/apt/sources.list.d)" = ubuntu.sources ] || { echo "unexpected apt sources" >&2; exit 1; }; \
    sed -i -E "s#^URIs: .*#URIs: https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/#" "$src"; \
    uris="$(grep '^URIs: ' "$src")"; \
    if [ -z "$uris" ] || grep -vxF "URIs: https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}/" <<<"$uris"; then \
      echo "$src does not point only at the snapshot" >&2; exit 1; \
    fi; \
    if [ -f /etc/apt/sources.list ] && grep -E '^[[:space:]]*deb' /etc/apt/sources.list; then \
      echo "/etc/apt/sources.list adds sources outside the snapshot" >&2; exit 1; \
    fi; \
    apt_tls=(-o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false); \
    apt-get "${apt_tls[@]}" update; \
    DEBIAN_FRONTEND=noninteractive apt-get "${apt_tls[@]}" install -y --no-install-recommends \
      ca-certificates curl git gcc libc6-dev python3 unzip xz-utils; \
    rm -rf /var/lib/apt/lists/*; \
    [ "$(python3 --version)" = "Python ${PYTHON_VERSION}" ] || { echo "snapshot python3 is $(python3 --version), not ${PYTHON_VERSION}" >&2; exit 1; }

RUN curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip"; \
    echo "${BUN_SHA256}  /tmp/bun.zip" | sha256sum --check --strict; \
    unzip -q /tmp/bun.zip -d /tmp/bun; \
    install -m 0755 /tmp/bun/bun-linux-x64/bun /usr/local/bin/bun; \
    rm -rf /tmp/bun /tmp/bun.zip

RUN curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum --check --strict; \
    mkdir /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 --no-same-owner; \
    rm /tmp/node.tar.xz

# Temurin release tags spell the build as `+`, file names as `_`.
RUN tag="jdk-${JRE_VERSION/+/%2B}"; file="OpenJDK${JAVA_VERSION}U-jre_x64_linux_hotspot_${JRE_VERSION/+/_}.tar.gz"; \
    curl -fsSL -o /tmp/jre.tar.gz "https://github.com/adoptium/temurin${JAVA_VERSION}-binaries/releases/download/${tag}/${file}"; \
    echo "${JRE_SHA256}  /tmp/jre.tar.gz" | sha256sum --check --strict; \
    mkdir /opt/java; \
    tar -xzf /tmp/jre.tar.gz -C /opt/java --strip-components=1 --no-same-owner; \
    rm /tmp/jre.tar.gz

ENV TLA2TOOLS=/opt/tla/tla2tools.jar
RUN mkdir /opt/tla; \
    curl -fsSL -o "$TLA2TOOLS" "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"; \
    echo "${TLA_SHA256}  $TLA2TOOLS" | sha256sum --check --strict

# A git commit id names its content, so the checkout needs no extra checksum.
RUN git clone --quiet https://github.com/bendlang/bend /opt/bend; \
    git -C /opt/bend checkout --quiet "$BEND_COMMIT"; \
    [ "$(git -C /opt/bend rev-parse HEAD)" = "$BEND_COMMIT" ]; \
    printf '#!/bin/sh\nexec bun /opt/bend/bend2/main.ts "$@"\n' > /usr/local/bin/bend; \
    chmod 0755 /usr/local/bin/bend

ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/opt/node/bin:/opt/java/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init"; \
    echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum --check --strict; \
    chmod 0755 /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none; \
    rm /tmp/rustup-init

# The toolchain, its components and its targets come from rust-toolchain.toml:
# with no arguments, `rustup toolchain install` installs the one it names.
COPY rust-toolchain.toml /opt/check/rust-toolchain.toml
RUN cd /opt/check; \
    rustup toolchain install; \
    channel="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"; \
    [[ "$(rustc --version)" == "rustc $channel "* ]]; \
    cargo clippy --version >/dev/null; \
    rustup target list --installed | grep -x wasm32-unknown-unknown >/dev/null

# Cargo dependencies, baked in, so the run needs no network. The manifests sit
# in a skeleton with empty targets; only the registry it fills is kept for the
# run, which copies it into a writable CARGO_HOME.
COPY Cargo.toml Cargo.lock /opt/check-skel/
COPY crates/ /opt/check-skel/crates/
RUN cd /opt/check-skel; \
    cp /opt/check/rust-toolchain.toml .; \
    for crate in crates/*/; do mkdir -p "$crate/src"; : > "$crate/src/lib.rs"; : > "$crate/src/main.rs"; done; \
    cargo fetch --locked; \
    chmod -R a+rX /opt/cargo /opt/rustup

# What the entrypoint compares with the checkout it is given.
COPY Cargo.lock /opt/check/Cargo.lock
COPY ci/check.Dockerfile ci/check-entrypoint.sh /opt/check/ci/

# The base image's `ubuntu` user is uid 1000. /work is where the run's scratch
# volume is mounted; a new volume takes this directory's owner.
RUN [ "$(id -u ubuntu)" = 1000 ]; mkdir /work; chown 1000:1000 /work
# A missing tool fails pins_check.py require instead of printing SKIPPED.
ENV CI=true
USER 1000:1000
WORKDIR /work
ENTRYPOINT ["bash", "/opt/check/ci/check-entrypoint.sh"]
