# File: Dockerfile
# --- Build Stage ---
FROM rust:trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Build Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git binutils \
    libssl-dev libxml2-dev \
    libopenconnect-dev \
    libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev \
    patch gettext autopoint bison flex \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# 2. Clone Source
RUN git clone --branch v2.5.1 https://github.com/yuezk/GlobalProtect-openconnect.git . && \
    git submodule init && \
    git config submodule.crates/openconnect/deps/libxml2.url https://github.com/GNOME/libxml2.git && \
    git submodule update --recursive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 3. Apply Patches
RUN grep -rl "cannot be run as root" . | xargs -r sed -i 's/if.*root.*/if false {/' && \
    sed -i 's/let no_gui = false;/let no_gui = true;/' apps/gpservice/src/cli.rs

# 4. Compilation
ENV CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_PANIC=abort

RUN echo 'fn main() { if std::net::TcpStream::connect("127.0.0.1:8001").is_ok() { std::process::exit(0); } else { std::process::exit(1); } }' > healthcheck.rs && \
    rustc -O healthcheck.rs -o healthcheck && \
    cargo build --release --bin gpclient --no-default-features && \
    cargo build --release --bin gpservice && \
    cargo build --release --bin gpauth --no-default-features && \
    strip target/release/gpclient target/release/gpservice target/release/gpauth

# --- Runtime Stage (Final Image) ---
FROM python:3.14-slim

# ARGs used to pull the correct architecture and version for gost
ARG TARGETARCH=amd64
ARG GOST_VERSION="3.2.6"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Catch pipe failures during the build process
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# 5. Install Runtime System Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables iproute2 util-linux procps tzdata \
    vpnc-scripts ca-certificates \
    libxml2 libgnutls30t64 liblz4-1 libpsl5 libsecret-1-0 openssl \
    sudo libcap2-bin dnsmasq ipset \
    && rm -rf /var/lib/apt/lists/*

# 6. Install Python Dependencies
# Required for the TOFU Ed25519 pairing architecture
RUN pip install --no-cache-dir --break-system-packages cryptography==46.0.5

# 7. Download GOST and Purge Wget
RUN apt-get update && apt-get install -y --no-install-recommends wget \
    && if [ "$TARGETARCH" = "arm" ]; then \
    echo "Error: 32-bit ARM (arm/v7) is not supported by GOST v${GOST_VERSION} prebuilts." >&2 && exit 1; \
    else \
    wget -q "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && wget -q "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/checksums.txt" \
    && grep "gost_${GOST_VERSION}_linux_${TARGETARCH}.tar.gz" checksums.txt | sha256sum -c \
    && tar -xzf "gost_${GOST_VERSION}_linux_${TARGETARCH}.tar.gz" gost \
    && mv gost /usr/bin/gost \
    && chmod +x /usr/bin/gost \
    && rm "gost_${GOST_VERSION}_linux_${TARGETARCH}.tar.gz" checksums.txt; \
    fi \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# 8. Setup User
RUN useradd -m -s /bin/bash gpuser && \
    printf '%s\n' \
    "Cmnd_Alias GP_RUNTIME = /usr/bin/gpclient, /usr/bin/gpservice" \
    "Cmnd_Alias GP_PROCCTL = /usr/bin/pkill -x gpclient, /usr/bin/pkill -x gpservice, /usr/bin/pkill -9 -x gpclient, /usr/bin/pkill -9 -x gpservice, /usr/bin/pgrep -x gpclient, /usr/bin/pgrep -x gpservice, /bin/true, /usr/bin/true" \
    "gpuser ALL=(root) NOPASSWD: GP_RUNTIME, GP_PROCCTL" \
    > /etc/sudoers.d/gpuser && \
    chmod 0440 /etc/sudoers.d/gpuser && \
    visudo -cf /etc/sudoers.d/gpuser

# 9. Copy Binaries
COPY --from=builder \
    /usr/src/app/target/release/gpclient \
    /usr/src/app/target/release/gpservice \
    /usr/src/app/target/release/gpauth \
    /usr/bin/
COPY --from=builder /usr/src/app/healthcheck /usr/bin/healthcheck

# 10. Set Capabilities
RUN setcap 'cap_net_admin,cap_net_bind_service+ep' /usr/bin/gpservice && \
    ldconfig

# 11. Setup App Environment
RUN mkdir -p /var/www/html /opt/gp-proxy /tmp/gp-logs /run/dbus && \
    chown -R gpuser:gpuser /var/www/html /opt/gp-proxy /tmp/gp-logs /run/dbus && \
    mv /usr/share/vpnc-scripts/vpnc-script /usr/share/vpnc-scripts/vpnc-script-orig

# Copy the frontend web directory and python backend with correct user permissions
COPY --chown=gpuser:gpuser web/ /var/www/html/
COPY --chown=gpuser:gpuser backend/ /opt/gp-proxy/
COPY backend/vpnc-wrapper.sh /usr/share/vpnc-scripts/vpnc-script
COPY entrypoint.sh /entrypoint.sh

# Ensure proper execution rights
RUN chmod +x /opt/gp-proxy/server.py /opt/gp-proxy/control_listener.py /opt/gp-proxy/stdin_proxy.py /usr/share/vpnc-scripts/vpnc-script /entrypoint.sh

# 12. Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /usr/bin/healthcheck || exit 1

EXPOSE 1080 1084 1085 8001 8080 8388 8443
ENTRYPOINT ["/entrypoint.sh"]
