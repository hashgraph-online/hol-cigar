# syntax=docker/dockerfile:1.7

FROM rust:1.92.0-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --locked --release --package cigar-daemon --bin cigard \
    && install -d -m 0750 \
        /image/state \
        /image/state/project \
        /image/state/blobs \
        /image/state/blob-keys \
        /image/effect-checkpoints \
        /image/runtime \
    && install -d -m 0555 /image/config

FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="CIGAR daemon" \
      org.opencontainers.image.description="Capability-limited CIGAR context service" \
      org.opencontainers.image.url="https://hol.org/cigar" \
      org.opencontainers.image.source="https://github.com/CIGAR/cigar" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder --chown=0:0 --chmod=0555 /src/target/release/cigard /usr/local/bin/cigard
COPY --from=builder --chown=65532:65532 --chmod=0750 /image/state/ /var/lib/cigar/
COPY --from=builder --chown=65532:65532 --chmod=0700 /image/effect-checkpoints/ /var/lib/cigar-effect-checkpoints/
COPY --from=builder --chown=65532:65532 --chmod=0750 /image/runtime/ /run/cigar/
COPY --from=builder --chown=0:0 --chmod=0555 /image/config/ /etc/cigar/
COPY --chown=0:0 --chmod=0444 deploy/docker/cigard.example.toml /etc/cigar/cigard.toml

USER 65532:65532
WORKDIR /var/lib/cigar
EXPOSE 7443 7444
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/cigard"]
CMD ["serve", "--config", "/etc/cigar/cigard.toml"]
