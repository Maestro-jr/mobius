# themob MobSF client: the container that speaks HTTP so the engine does not.
#
# Run by themob/sandbox/service.py on the service's *internal* network, which is
# the one place a themob container gets a network at all. Everything else is
# unchanged: --read-only, --cap-drop ALL, --user 65534:65534, and the sample
# mounted read-only at /input.
#
# Standard library only. A client that moves one file and reads some JSON does
# not need a dependency tree, and every package added here would be one more
# thing running beside a hostile sample.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY analyze.py /opt/themob/analyze.py

# Prove it at least loads at build time, so a syntax error never reaches a
# tester as "MobSF found nothing".
RUN python -c "import py_compile; py_compile.compile('/opt/themob/analyze.py', doraise=True)" \
 && mkdir -p /input /work \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py

USER 65534:65534
WORKDIR /work

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
