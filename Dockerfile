# Builds the `manytier` binary against musl for a small, static final image.
FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# rust-toolchain.toml pins a specific channel, so the musl target must be
# added after COPY (once that pinned toolchain is in play), not against this
# base image's own default toolchain.
RUN rustup target add x86_64-unknown-linux-musl

# Ubuntu/Debian's musl-tools package only ships an unprefixed `musl-gcc`, not
# the `x86_64-linux-musl-gcc` name cc-rs looks for by default (needed to
# cross-compile rusqlite's bundled sqlite3 C sources).
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p zerotier-cli

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/manytier /usr/local/bin/manytier

# The manytier CLI looks for ./authtoken.secret relative to the current
# directory when --auth-token isn't given. Setting the workdir to the data
# dir means `docker exec <container> manytier status` (etc.) finds the
# token the service running as CMD wrote into /data, with no extra flags.
WORKDIR /data
VOLUME ["/data"]
EXPOSE 9993/udp 9993/tcp

ENTRYPOINT ["manytier"]
CMD ["service", "--data-dir", "/data"]
