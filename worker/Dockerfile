# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM python:3.11-slim-trixie@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

ARG BOFA_VERSION=3.0.0-alpha.1
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/bofa \
    BOFA_BASE_PATH=/opt/bofa \
    BOFA_LOG_FORMAT=json \
    BOFA_LOG_LEVEL=INFO

WORKDIR /opt/bofa

COPY worker/requirements.txt /tmp/worker-requirements.txt
RUN python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --require-hashes \
      --requirement /tmp/worker-requirements.txt \
    && python -m pip uninstall --yes setuptools wheel packaging \
    && python -m pip uninstall --yes pip \
    && rm /tmp/worker-requirements.txt \
    && groupadd --gid 65532 bofa \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin bofa \
    && mkdir -p \
      /opt/bofa/config \
      /opt/bofa/logs \
      /opt/bofa/output \
      /opt/bofa/reports \
      /run/bofa-out \
      /var/lib/bofa-worker/claims \
    && chown -R 65532:65532 \
      /opt/bofa/config \
      /opt/bofa/logs \
      /opt/bofa/output \
      /opt/bofa/reports \
      /run/bofa-out \
      /var/lib/bofa-worker

COPY --chown=65532:65532 core/__init__.py core/cancellation.py ./core/
COPY --chown=65532:65532 core/execution ./core/execution
COPY --chown=65532:65532 \
  worker/__init__.py \
  worker/adapter_executor.py \
  worker/catalog.py \
  worker/entrypoint.py \
  worker/runtime.py \
  worker/catalog.json \
  ./worker/
COPY --chown=65532:65532 scripts/forensics/hash_calculator.py ./scripts/forensics/hash_calculator.py
COPY --chown=65532:65532 scripts/forensics/hash_calculator.yaml ./scripts/forensics/hash_calculator.yaml

LABEL org.opencontainers.image.title="BOFA one-job worker" \
      org.opencontainers.image.description="Deny-by-default OCI worker for signed BOFA JobSpecs" \
      org.opencontainers.image.source="https://github.com/descambiado/BOFA" \
      org.opencontainers.image.documentation="https://github.com/descambiado/BOFA/blob/main/worker/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${BOFA_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "worker.entrypoint"]
