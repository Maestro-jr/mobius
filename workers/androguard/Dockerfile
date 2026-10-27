# themob androguard worker: unpack and inventory an APK.
#
# Built by `python -m themob.sandbox.build` (or `docker build -t themob/androguard:1 .`)
# and run by themob/sandbox/runner.py with:
#   --network none --read-only --cap-drop ALL --user 65534:65534
# so this image must work with no network, no writable root filesystem, and no
# privileges. Everything it needs is baked in at build time.
FROM python:3.12-slim-bookworm

# No .pyc writes (the root filesystem is read-only at runtime) and unbuffered
# stdout so the JSON document is not lost if the container is killed.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt
# No trailing `|| true` here, and no invented flags. An earlier version had
# both: `--require-hashes=false` is not a pip option, so pip exited non-zero,
# and the `|| true` turned that into a successful build, producing an image
# with no androguard in it, which only surfaced when a container actually ran.
# A worker build must fail loudly rather than ship a tool that is not there.
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm -f /tmp/requirements.txt \
 && find /usr/local/lib/python3.12 -name '__pycache__' -type d -prune -exec rm -rf {} +

# Prove the tool is importable at build time, so a broken image never reaches a
# tester as "0 entities found".
RUN python -c "import androguard, asn1crypto; print('androguard', androguard.__version__)"

COPY analyze.py /opt/themob/analyze.py

# The runner mounts the sample read-only at /input and sets the workdir to /work;
# both must exist and be readable by uid 65534.
RUN mkdir -p /input /output /work \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py

USER 65534:65534
WORKDIR /work

# argv form: no shell, so nothing in the sample's filename can be interpreted.
ENTRYPOINT ["python", "/opt/themob/analyze.py"]
