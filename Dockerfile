# SEVER console — production image (rule 10: live deployment artifact)
FROM python:3.11-slim

WORKDIR /app

# the console + its engine client; openai stays optional (OfflineNarrator by default)
COPY pyproject.toml README.md ./
COPY sever ./sever
RUN pip install --no-cache-dir -e ".[console]"

# the official BloodHound CE sample estate (Apache-2.0, SpecterOps) so the
# console can auto-load the demo tenant at boot without any manual step
RUN mkdir -p data/ad_sample \
    && apt-get update -qq && apt-get install -qq -y curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sL https://raw.githubusercontent.com/SpecterOps/BloodHound-Docs/main/docs/assets/sample-data/ad_sampledata.zip \
       -o /tmp/ad.zip && unzip -q /tmp/ad.zip -d data/ad_sample && rm /tmp/ad.zip

ENV SEVER_SAMPLE_DIR=/app/data/ad_sample \
    SEVER_FALKOR_GRAPH=sever_demo \
    PORT=8000

EXPOSE 8000

# engine liveness in `docker ps`: /api/state is the same probe the Render
# health check uses; the UI flips to "engine unreachable" when it 500s
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -sf http://localhost:${PORT:-8000}/api/state || exit 1

CMD ["sh", "-c", "uvicorn sever.console.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
