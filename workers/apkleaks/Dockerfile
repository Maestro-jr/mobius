# themob apkleaks worker: Android-specific secrets, URIs and endpoints.
#
# Run by themob/sandbox/runner.py with --network none, --read-only,
# --cap-drop ALL and --user 65534:65534. Everything is baked in at build time.
#
# apkleaks is MIT and invoked as a subprocess, never imported. It complements
# gitleaks rather than repeating it: gitleaks matches provider credential
# formats but will not match a secret sitting between XML tags, and
# res/values/strings.xml is exactly where an Android app keeps an API key.
FROM eclipse-temurin:17-jre-jammy

# Pinned by version AND digest; the build fails loudly on a mismatch rather
# than shipping bytes nobody checked. Bump both lines together.
ARG JADX_VERSION=1.5.3
ARG JADX_SHA256=8280f3799c0273fe797a2bcd90258c943e451fd195f13d05400de5e6451d15ec

# -Duser.home is load-bearing, the same lesson the jadx worker learned: jadx
# resolves its config directory from the JVM's user.home property rather than
# $HOME, and uid 65534 has no passwd entry, so it resolves to "/" and jadx dies
# trying to create /.config on the read-only root filesystem.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    JAVA_TOOL_OPTIONS="-Djava.awt.headless=true -Dfile.encoding=UTF-8 -Duser.home=/tmp"

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip curl unzip \
 && rm -rf /var/lib/apt/lists/*

# apkleaks resolves its disassembler with which("jadx") and only falls back to
# downloading one when that misses. A download is impossible under --network
# none and it would prompt on stdin, so the launcher script has to be on PATH.
# This is why /opt/jadx/bin is kept here, unlike the jadx worker which removes
# it and calls the CLI class directly.
RUN curl -fL --retry 5 --retry-delay 3 --retry-all-errors \
      -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
 && echo "${JADX_SHA256}  /tmp/jadx.zip" > /tmp/jadx.sha256 \
 && sha256sum -c /tmp/jadx.sha256 \
 && mkdir -p /opt/jadx \
 && unzip -q /tmp/jadx.zip -d /opt/jadx \
 && rm -f /tmp/jadx.zip /tmp/jadx.sha256 \
 && chmod -R a+rX /opt/jadx \
 && chmod 0555 /opt/jadx/bin/jadx \
 && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

COPY requirements.txt /tmp/requirements.txt
# No trailing `|| true` on this line, and no invented flags. The androguard
# worker learned both the hard way: a `|| true` that trails a chain turns a
# failed pip into a successful build, and the image ships without the tool in
# it. That only surfaces when a container runs and reports finding nothing.
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt \
 && rm -f /tmp/requirements.txt

# Cache trimming is allowed to fail; installing is not, so it gets its own layer.
RUN find /usr/lib/python3 /usr/local/lib/python3.10 -name '__pycache__' \
      -type d -prune -exec rm -rf {} + 2>/dev/null || true

# Prove both halves work at build time, so a broken image never reaches a
# tester as "the scan found nothing".
RUN jadx --version && python3 -c "import apkleaks; print('apkleaks ok')"

COPY analyze.py /opt/themob/analyze.py

RUN mkdir -p /input /output /work \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py

USER 65534:65534
WORKDIR /work

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
