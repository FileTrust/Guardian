FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 libgcc-s1 util-linux \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/filetrust-guardian
COPY requirements.txt ./
RUN python -m venv .venv \
    && .venv/bin/python -m pip install --disable-pip-version-check --timeout 120 --retries 5 -r requirements.txt \
    && .venv/bin/python -m pip check
ENV PATH="/opt/filetrust-guardian/.venv/bin:${PATH}"
COPY . ./
RUN groupadd --gid 10001 ftguardian \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/filetrust-guardian --no-create-home --shell /usr/sbin/nologin ftguardian \
    && mkdir -p /var/lib/filetrust-guardian /etc/filetrust-guardian /run/filetrust-guardian .filetrust-updates \
    && chown 10001:10001 /var/lib/filetrust-guardian /etc/filetrust-guardian /run/filetrust-guardian \
    && chmod 0700 /var/lib/filetrust-guardian /etc/filetrust-guardian /run/filetrust-guardian
ENV HOME=/var/lib/filetrust-guardian TMPDIR=/run/filetrust-guardian FILETRUST_CONTAINER=1
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "/opt/filetrust-guardian/container_cli.py"]
CMD ["run"]
