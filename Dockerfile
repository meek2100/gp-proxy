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
RUN grep -rl "cannot be run as root" . | xargs sed -i 's/if.*root.*/if false {/'
RUN sed -i 's/let no_gui = false;/let no_gui = true;/' apps/gpservice/src/cli.rs

# 4. Compilation
ENV CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_PANIC=abort

RUN echo 'fn main() { if std::net::TcpStream::connect("127.0.0.1:8001").is_ok() { std::process::exit(0); } else { std::process::exit(1); } }' > healthcheck.rs && \
    rustc -O healthcheck.rs -o healthcheck

RUN cargo build --release --bin gpclient --no-default-features && \
    cargo build --release --bin gpservice && \
    cargo build --release --bin gpauth --no-default-features && \
    strip target/release/gpclient target/release/gpservice target/release/gpauth

# --- Runtime Stage (Final Image) ---
FROM python:3.14-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 5. Install Runtime Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    microsocks iptables iproute2 util-linux procps tzdata \
    vpnc-scripts ca-certificates \
    libxml2 libgnutls30t64 liblz4-1 libpsl5 libsecret-1-0 openssl \
    sudo libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# 6. Setup User
RUN useradd -m -s /bin/bash gpuser
RUN echo "gpuser ALL=(root) NOPASSWD: /usr/bin/gpclient, /usr/bin/pkill" > /etc/sudoers.d/gpuser && \
    chmod 0440 /etc/sudoers.d/gpuser

# 7. Copy Binaries
COPY --from=builder \
    /usr/src/app/target/release/gpclient \
    /usr/src/app/target/release/gpservice \
    /usr/src/app/target/release/gpauth \
    /usr/bin/
COPY --from=builder /usr/src/app/healthcheck /usr/bin/healthcheck

# 8. Set Capabilities
RUN setcap 'cap_net_admin,cap_net_bind_service+ep' /usr/bin/gpservice && \
    ldconfig

# 9. Setup App
RUN mkdir -p /var/www/html /tmp/gp-logs /run/dbus && \
    chown -R gpuser:gpuser /var/www/html /tmp/gp-logs /run/dbus

COPY server.py index.html /var/www/html/
COPY assets/gp-proxy /var/www/html/assets/gp-proxy/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
ENV VPN_MODE=standard
ENV LOG_LEVEL=INFO

# 10. Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /usr/bin/healthcheck || exit 1

EXPOSE 1080 8001
ENTRYPOINT ["/entrypoint.sh"]
