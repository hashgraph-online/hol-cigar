ARG NODE_IMAGE
FROM ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc AS uv
FROM ${NODE_IMAGE}
RUN if command -v apk >/dev/null; then apk add --no-cache git; \
    else apt-get update && apt-get install -y --no-install-recommends git; fi
COPY --from=uv /uv /usr/local/bin/uv
ARG CIGAR_PYTHON_VERSION
ENV UV_PYTHON_INSTALL_DIR=/opt/cigar-python
ENV CIGAR_PYTHON_VERSION=${CIGAR_PYTHON_VERSION}
RUN uv python install --no-bin "${CIGAR_PYTHON_VERSION}"
COPY context-python.sh /usr/local/bin/context-test-python
ENTRYPOINT ["/bin/sh", "/usr/local/bin/context-test-python"]
