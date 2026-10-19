FROM python:3.11-slim AS base

LABEL maintainer="mrhenrike <henrique.santos@uniaogeek.com.br>"
LABEL org.opencontainers.image.source="https://github.com/mrhenrike/WirelessXPL-Forge"
LABEL org.opencontainers.image.description="WirelessXPL: wireless protocol exploitation framework"

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash xpluser

WORKDIR /opt/wirelessxpl

COPY pyproject.toml README.md LICENSE ./
COPY wirelessxpl/ wirelessxpl/

RUN pip install --no-cache-dir ".[dev]"

USER xpluser

ENTRYPOINT ["wxf"]
CMD ["--help"]
