# themob nativelib worker: read the ELF headers of the .so files.
#
# Built by `python -m themob.sandbox.build` (or `docker build -t themob/nativelib:1 .`)
# and run by themob/sandbox/runner.py with:
#   --network none --read-only --cap-drop ALL --user 65534:65534
# so this image must work with no network, no writable root filesystem, and no
# privileges.
#
# This worker never sees the APK. It reads /scan, the decoded tree an earlier
# stage produced, and parses each .so with a small hand-rolled ELF reader that
# never executes a byte of what it reads. No third-party dependency: the parser
# is a few structs, so there is nothing to pin and nothing to pull.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

COPY analyze.py /opt/themob/analyze.py

# Prove it imports and its ELF reader is callable at build time, so a broken
# image never reaches a tester as "0 libraries".
RUN python -c "import sys; sys.path.insert(0, '/opt/themob'); import analyze; assert analyze.inspect_elf(b'not an elf') is None; print('nativelib ok')"

# The runner mounts /scan read-only and sets the workdir to /work.
RUN mkdir -p /scan /output /work \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py

USER 65534:65534
WORKDIR /work

# argv form: no shell, so nothing in a filename can be interpreted.
ENTRYPOINT ["python", "/opt/themob/analyze.py"]
