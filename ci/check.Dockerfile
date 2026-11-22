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
ARG CHECK_UBUNTU_SNAPSHOT
ARG CHECK_PYTHON_VERSION
ARG BUN_VERSION
ARG CHECK_BUN_SHA256
ARG NODE_VERSION
ARG CHECK_NODE_SHA256
ARG JAVA_VERSION
ARG CHECK_JRE_VERSION
ARG CHECK_JRE_SHA256
ARG BEND_COMMIT
ARG TLA_VERSION
ARG TLA_SHA256
ARG CHECK_RUSTUP_VERSION
ARG CHECK_RUSTUP_INIT_SHA256
ARG CHECK_INRELEASE_NOBLE
ARG CHECK_INRELEASE_NOBLE_UPDATES
ARG CHECK_INRELEASE_NOBLE_BACKPORTS
ARG CHECK_INRELEASE_NOBLE_SECURITY

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
    same CHECK_BASE_IMAGE "$CHECK_BASE_IMAGE"; same CHECK_UBUNTU_SNAPSHOT "$CHECK_UBUNTU_SNAPSHOT"; \
    same CHECK_PYTHON_VERSION "$CHECK_PYTHON_VERSION"; same BUN_VERSION "$BUN_VERSION"; \
    same CHECK_BUN_SHA256 "$CHECK_BUN_SHA256"; same NODE_VERSION "$NODE_VERSION"; \
    same CHECK_NODE_SHA256 "$CHECK_NODE_SHA256"; same JAVA_VERSION "$JAVA_VERSION"; \
    same CHECK_JRE_VERSION "$CHECK_JRE_VERSION"; same CHECK_JRE_SHA256 "$CHECK_JRE_SHA256"; \
    same BEND_COMMIT "$BEND_COMMIT"; same TLA_VERSION "$TLA_VERSION"; \
    same TLA_SHA256 "$TLA_SHA256"; same CHECK_RUSTUP_VERSION "$CHECK_RUSTUP_VERSION"; \
    same CHECK_RUSTUP_INIT_SHA256 "$CHECK_RUSTUP_INIT_SHA256"; \
    same CHECK_INRELEASE_NOBLE "$CHECK_INRELEASE_NOBLE"; \
    same CHECK_INRELEASE_NOBLE_UPDATES "$CHECK_INRELEASE_NOBLE_UPDATES"; \
    same CHECK_INRELEASE_NOBLE_BACKPORTS "$CHECK_INRELEASE_NOBLE_BACKPORTS"; \
    same CHECK_INRELEASE_NOBLE_SECURITY "$CHECK_INRELEASE_NOBLE_SECURITY"; \
    [[ "$CHECK_BASE_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "CHECK_BASE_IMAGE must be pinned by digest" >&2; exit 1; }; \
    [[ "$NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "NODE_VERSION must be an exact version" >&2; exit 1; }; \
    [[ "$CHECK_JRE_VERSION" == "$JAVA_VERSION".* ]] || { echo "CHECK_JRE_VERSION $CHECK_JRE_VERSION is not Java $JAVA_VERSION" >&2; exit 1; }; \
    for sum in "$CHECK_BUN_SHA256" "$CHECK_NODE_SHA256" "$CHECK_JRE_SHA256" "$TLA_SHA256" "$CHECK_RUSTUP_INIT_SHA256" \
               "$CHECK_INRELEASE_NOBLE" "$CHECK_INRELEASE_NOBLE_UPDATES" "$CHECK_INRELEASE_NOBLE_BACKPORTS" \
               "$CHECK_INRELEASE_NOBLE_SECURITY"; do \
      [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || { echo "not a sha256: $sum" >&2; exit 1; }; \
    done

# Ubuntu packages from a fixed snapshot of the archive, so a rebuild gets the
# same python3, git and gcc. The base image has no CA certificates yet and the
# snapshot service redirects http to https, so these apt runs skip TLS peer
# checks. apt's trust is the archive's signed InRelease and the hashes it
# lists, as with the image's default http:// sources. A signature alone would
# also accept an older signed snapshot replayed in its place (noble's InRelease
# carries no Valid-Until), so each suite's InRelease must also have the sha256
# pinned in ci/pins.env. That pins every package, dependencies included, where
# pinning package versions would pin only the ones named here.
RUN src=/etc/apt/sources.list.d/ubuntu.sources; \
    [ "$(ls -A /etc/apt/sources.list.d)" = ubuntu.sources ] || { echo "unexpected apt sources" >&2; exit 1; }; \
    sed -i -E "s#^URIs: .*#URIs: https://snapshot.ubuntu.com/ubuntu/${CHECK_UBUNTU_SNAPSHOT}/#" "$src"; \
    uris="$(grep '^URIs: ' "$src")"; \
    if [ -z "$uris" ] || grep -vxF "URIs: https://snapshot.ubuntu.com/ubuntu/${CHECK_UBUNTU_SNAPSHOT}/" <<<"$uris"; then \
      echo "$src does not point only at the snapshot" >&2; exit 1; \
    fi; \
    if [ -f /etc/apt/sources.list ] && grep -E '^[[:space:]]*deb' /etc/apt/sources.list; then \
      echo "/etc/apt/sources.list adds sources outside the snapshot" >&2; exit 1; \
    fi; \
    apt_tls=(-o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false); \
    apt-get "${apt_tls[@]}" update; \
    declare -A want=([noble]="$CHECK_INRELEASE_NOBLE" [noble-updates]="$CHECK_INRELEASE_NOBLE_UPDATES" \
      [noble-backports]="$CHECK_INRELEASE_NOBLE_BACKPORTS" [noble-security]="$CHECK_INRELEASE_NOBLE_SECURITY"); \
    seen=0; \
    for f in /var/lib/apt/lists/*Release /var/lib/apt/lists/*Release.gpg; do \
      [ -e "$f" ] || continue; \
      suite="${f##*_dists_}"; suite="${suite%_*}"; \
      [ "$f" = "/var/lib/apt/lists/snapshot.ubuntu.com_ubuntu_${CHECK_UBUNTU_SNAPSHOT}_dists_${suite}_InRelease" ] \
        || { echo "unexpected apt index $f" >&2; exit 1; }; \
      [ -n "${want[$suite]:-}" ] || { echo "no pinned InRelease for suite $suite" >&2; exit 1; }; \
      echo "${want[$suite]}  $f" | sha256sum --check --strict; \
      seen=$((seen + 1)); \
    done; \
    [ "$seen" = "${#want[@]}" ] || { echo "expected ${#want[@]} pinned InRelease files, found $seen" >&2; exit 1; }; \
    DEBIAN_FRONTEND=noninteractive apt-get "${apt_tls[@]}" install -y --no-install-recommends \
      ca-certificates curl git gcc libc6-dev python3 unzip xz-utils; \
    rm -rf /var/lib/apt/lists/*; \
    [ "$(python3 --version)" = "Python ${CHECK_PYTHON_VERSION}" ] || { echo "snapshot python3 is $(python3 --version), not ${CHECK_PYTHON_VERSION}" >&2; exit 1; }

RUN curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip"; \
    echo "${CHECK_BUN_SHA256}  /tmp/bun.zip" | sha256sum --check --strict; \
    unzip -q /tmp/bun.zip -d /tmp/bun; \
    install -m 0755 /tmp/bun/bun-linux-x64/bun /usr/local/bin/bun; \
    rm -rf /tmp/bun /tmp/bun.zip

RUN curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"; \
    echo "${CHECK_NODE_SHA256}  /tmp/node.tar.xz" | sha256sum --check --strict; \
    mkdir /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 --no-same-owner; \
    rm /tmp/node.tar.xz

# Temurin release tags spell the build as `+`, file names as `_`.
RUN tag="jdk-${CHECK_JRE_VERSION/+/%2B}"; file="OpenJDK${JAVA_VERSION}U-jre_x64_linux_hotspot_${CHECK_JRE_VERSION/+/_}.tar.gz"; \
    curl -fsSL -o /tmp/jre.tar.gz "https://github.com/adoptium/temurin${JAVA_VERSION}-binaries/releases/download/${tag}/${file}"; \
    echo "${CHECK_JRE_SHA256}  /tmp/jre.tar.gz" | sha256sum --check --strict; \
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
RUN curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${CHECK_RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init"; \
    echo "${CHECK_RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum --check --strict; \
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

# The whole build context, which the entrypoint compares with the checkout it
# is given and hashes into the context hash it reports.
COPY ci/check-entrypoint.sh /opt/check/ci/check-entrypoint.sh
COPY . /opt/check-context/

# The base image's `ubuntu` user is uid 1000. /work is where the run's scratch
# volume is mounted; a new volume takes this directory's owner.
RUN [ "$(id -u ubuntu)" = 1000 ]; mkdir /work; chown 1000:1000 /work
# A missing tool fails pins_check.py require instead of printing SKIPPED.
ENV CI=true
USER 1000:1000
WORKDIR /work
ENTRYPOINT ["bash", "/opt/check/ci/check-entrypoint.sh"]
