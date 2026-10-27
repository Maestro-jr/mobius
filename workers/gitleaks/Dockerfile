# themob gitleaks worker: scan decoded resources and decompiled sources.
#
# Run by themob/sandbox/runner.py with --network none, --read-only,
# --cap-drop ALL and --user 65534:65534. Everything is baked in at build time.
#
# gitleaks is MIT licensed and invoked here as a subprocess, never imported.
# The arms-length rule from the build plan's section 6 applies to permissive
# tools too, because the sandbox boundary is the same boundary.
#
# This worker never sees the APK. It reads /scan, which is the artifacts an
# earlier stage already produced, so a malformed package cannot reach it.
FROM alpine:3.20

# Pinned by version AND digest, taken from the release's own checksums.txt.
# themob will not run an analyzer whose bytes it has not checked. To bump,
# change both lines together; the build fails loudly on a mismatch.
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache

RUN apk add --no-cache python3 curl \
 && curl -fL --retry 5 --retry-delay 3 --retry-all-errors \
      -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
 && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" > /tmp/gitleaks.sha256 \
 && sha256sum -c /tmp/gitleaks.sha256 \
 && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
 && rm -f /tmp/gitleaks.tar.gz /tmp/gitleaks.sha256 \
 && apk del curl \
 && chmod 0555 /usr/local/bin/gitleaks

# Prove the binary runs at build time, so a broken image never reaches a tester
# as "the scan found nothing".
RUN gitleaks version

COPY analyze.py /opt/themob/analyze.py

RUN mkdir -p /input /output /work /scan \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py

USER 65534:65534
WORKDIR /work

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
