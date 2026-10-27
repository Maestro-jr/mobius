# themob apktool worker: decode resources and the manifest.
#
# Run by themob/sandbox/runner.py with --network none, --read-only,
# --cap-drop ALL and --user 65534:65534, so everything is baked in at build
# time and nothing is fetched at run time.
#
# apktool is Apache-2.0 and invoked here as a subprocess, never imported,
# the arms-length rule from the build plan's §6 applies to permissive tools too,
# because the sandbox boundary is the same boundary.
FROM eclipse-temurin:17-jre-alpine

# Pinned by version AND digest. `themob` will not run an analyzer whose bytes it
# has not checked: a security tool that ships an unverified download is the
# problem it claims to look for. To bump, change both lines together, the
# build fails loudly on a mismatch rather than proceeding.
ARG APKTOOL_VERSION=2.11.1
ARG APKTOOL_SHA256=4920d21254ab9275d402f8cc30e5cef55a4e726c434daeaa487a238457efbfb5

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_CONFIG_HOME=/tmp/.config \
    XDG_CACHE_HOME=/tmp/.cache \
    JAVA_TOOL_OPTIONS="-Djava.awt.headless=true -Dfile.encoding=UTF-8 -Duser.home=/tmp"

RUN apk add --no-cache python3 py3-yaml \
 && wget -q -O /tmp/apktool.jar \
      "https://repo1.maven.org/maven2/org/apktool/apktool-cli/${APKTOOL_VERSION}/apktool-cli-${APKTOOL_VERSION}.jar" \
 && echo "${APKTOOL_SHA256}  /tmp/apktool.jar" > /tmp/apktool.sha256 \
 && sha256sum -c /tmp/apktool.sha256 \
 && mkdir -p /opt/apktool \
 && mv /tmp/apktool.jar /opt/apktool/apktool.jar \
 && rm -f /tmp/apktool.sha256

# Prove the jar runs at build time, so a broken image never reaches a tester
# as "decode produced nothing".
RUN java -jar /opt/apktool/apktool.jar --version

COPY analyze.py /opt/themob/analyze.py

# The runner mounts the sample read-only at /input and a writable /output, and
# sets the workdir to /work. apktool also wants a writable home for its
# framework cache; the runner gives it a tmpfs at /tmp.
ENV HOME=/tmp \
    APKTOOL_JAR=/opt/apktool/apktool.jar
RUN mkdir -p /input /output /work \
 && chmod 0555 /opt/themob /opt/apktool /work \
 && chmod 0444 /opt/themob/analyze.py /opt/apktool/apktool.jar

USER 65534:65534
WORKDIR /work

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
