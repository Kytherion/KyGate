# KyGate Guard: the ML service next to the gateway. It detects; the gateway enforces.
#
#   docker build -t kygate-guard:0.1.0 guard/                          # recognizers only
#   docker build -t kygate-guard:0.1.0-ml --build-arg EXTRAS=ml guard/  # with the ML software
#
# Model packs are never downloaded by the image or at start. Pull them once,
# into a volume or a host directory, and mount it on /models:
#   docker run --rm -v kygate-models:/models kygate-guard:0.1.0-ml models pull            (the default pack)
#   docker run --rm -v kygate-models:/models kygate-guard:0.1.0-ml models pull personal-data   (an add-on)
FROM python:3.12-slim
ARG EXTRAS=""
RUN useradd --create-home --uid 10002 guard && mkdir /models && chown guard:guard /models
WORKDIR /app
COPY pyproject.toml README.md NOTICE ./
COPY kygate_guard ./kygate_guard
RUN if [ -n "$EXTRAS" ]; then pip install --no-cache-dir ".[$EXTRAS]"; else pip install --no-cache-dir .; fi && rm -rf /root/.cache
USER guard
ENV KYGATE_GUARD_MODELS=/models
VOLUME /models
EXPOSE 4002
# "models ..." manages packs; anything else starts the server.
ENTRYPOINT ["/bin/sh", "-c", "if [ \"$1\" = models ]; then exec kygate-guard \"$@\"; else exec kygate-guard --listen 0.0.0.0:4002 \"$@\"; fi", "--"]
