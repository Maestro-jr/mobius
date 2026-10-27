# themob jadx worker: decompile DEX to Java.
#
# Run by themob/sandbox/runner.py with --network none, --read-only,
# --cap-drop ALL and --user 65534:65534. Everything is baked in at build time.
#
# jadx is Apache-2.0 and invoked as a subprocess, never imported, the
# arms-length rule from the build plan's §6 applies to permissive tools too,
# because the sandbox boundary is the same boundary.
FROM eclipse-temurin:17-jre-alpine

# Pinned by version AND digest; the build fails loudly on a mismatch rather
# than shipping bytes nobody checked. Bump both lines together.
# The release archive is ~111 MB. An earlier pin here was the hash of a
# *truncated* download that still looked plausible at 34 MB. `sha256sum -c`
# rejected it at build time, which is exactly why the digest is pinned at all.
# When bumping, verify the archive opens as a zip before trusting its hash.
ARG JADX_VERSION=1.5.3
ARG JADX_SHA256=8280f3799c0273fe797a2bcd90258c943e451fd195f13d05400de5e6451d15ec

# -Duser.home is load-bearing. jadx resolves its config directory from the JVM's
# user.home property, not from $HOME, and uid 65534 has no passwd entry, so it
# resolves to "/", jadx tries to create /.config on the read-only root
# filesystem, and the process dies during plugin loading before it reads a byte
# of the sample. XDG_* covers tools that read those instead.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    JAVA_TOOL_OPTIONS="-Djava.awt.headless=true -Dfile.encoding=UTF-8 -Duser.home=/tmp"

# curl rather than busybox wget: the release URL redirects to GitHub's object
# store, and `wget -q` reports a redirect failure by exiting 1 with no message
# at all, which is a miserable thing to debug. `-fL --retry` follows the
# redirect, fails loudly on an HTTP error, and survives a flaky link.
RUN apk add --no-cache python3 curl unzip \
 && curl -fL --retry 5 --retry-delay 3 --retry-all-errors \
      -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
 && echo "${JADX_SHA256}  /tmp/jadx.zip" > /tmp/jadx.sha256 \
 && sha256sum -c /tmp/jadx.sha256 \
 && mkdir -p /opt/jadx \
 && unzip -q /tmp/jadx.zip -d /opt/jadx \
 && rm -f /tmp/jadx.zip /tmp/jadx.sha256 \
 && apk del curl unzip \
 # The launcher scripts are unused: the worker calls the CLI class directly, so
 # nothing in the container depends on a shell.
 && rm -rf /opt/jadx/bin

# Prove the CLI class resolves at build time; the worker invokes it directly
# rather than through the launcher scripts, which are removed above.
RUN java -cp "/opt/jadx/lib/*" jadx.cli.JadxCLI --version

COPY analyze.py /opt/themob/analyze.py

# The runner mounts the sample read-only at /input and a writable /output, and
# gives the container a tmpfs at /tmp for scratch, jadx needs a writable HOME.
ENV HOME=/tmp \
    JADX_LIB=/opt/jadx/lib
RUN mkdir -p /input /output /work \
 && chmod -R a+rX /opt/jadx \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py

USER 65534:65534
WORKDIR /work

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
