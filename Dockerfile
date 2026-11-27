# The brainproxy CLI for headless and CI use. See "Container image" in docs/MANUAL.md.
#   docker build -t brainproxy .
#   docker run --rm -v brainproxy:/work brainproxy capabilities

# On Alpine the Rust target is musl, so this is the same kind of static binary as the release
# downloads, for whichever architecture builds it.
FROM rust:1.100.0-alpine3.24@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock zap-sync.json ./
COPY crates ./crates
RUN cargo build --release --locked -p brainproxy

# Alpine rather than scratch: CI systems expect a shell, and `apk` can add Chromium for
# `crawl --browser` (left out here: it takes the image from about 30 MB to over 800 MB).
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.title="brainproxy" \
      org.opencontainers.image.source="https://github.com/r4nd0mth1ngs/brainproxy" \
      org.opencontainers.image.licenses="Apache-2.0"
# UID 1000 is the usual first user on a Linux host, so most bind mounts work without --user.
RUN adduser -D -u 1000 brainproxy && install -d -o brainproxy -g brainproxy /work
COPY --from=build /src/target/release/brainproxy /usr/local/bin/brainproxy
COPY LICENSE NOTICE /usr/share/licenses/brainproxy/
# The CA stays with the project on the volume: it survives the container and works under any --user.
ENV BRAINPROXY_HOME=/work/.brainproxy
USER brainproxy
WORKDIR /work
EXPOSE 8080
ENTRYPOINT ["brainproxy"]
CMD ["--help"]
