# themob iOS unpack worker: unpack and inventory an .ipa.
#
# Built by `python -m themob.sandbox.build` (or `docker build -t themob/ios-unpack:1 .`)
# and run by themob/sandbox/runner.py with:
#   --network none --read-only --cap-drop ALL --user 65534:65534
# so this image must work with no network, no writable root filesystem, and no
# privileges. It writes scratch only to the /tmp tmpfs the runner provides.
FROM python:3.12-slim-bookworm

# No .pyc writes (the root filesystem is read-only at runtime) and unbuffered
# stdout so the JSON document is not lost if the container is killed.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /tmp/requirements.txt
# Fail loudly: no `|| true`, no invented flags. A worker that builds green but
# ships without its parser only surfaces as "0 entities found" when a container
# runs, which is the worst time to learn the image is empty.
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm -f /tmp/requirements.txt \
 && find /usr/local/lib/python3.12 -name '__pycache__' -type d -prune -exec rm -rf {} +

# Prove the tool is importable at build time, so a broken image never reaches a
# tester as an empty result.
RUN python -c "import lief; print('lief', lief.__version__)"

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
