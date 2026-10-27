# themob SBOM worker: catalog what the app bundles, then match it for CVEs.
#
# Run by themob/sandbox/runner.py with --network none, --read-only,
# --cap-drop ALL and --user 65534:65534. Everything is baked in at build time.
#
# syft and grype are both Apache-2.0 and invoked here as subprocesses, never
# imported, which is the same arms-length rule the other workers follow.
#
# Pinned by digest rather than tag. A tag is a moving pointer and "v1.51.1"
# can be repushed; a digest cannot. This is the same guarantee the other
# workers get from checksumming a release archive, obtained from the vendor's
# own published artifact instead of a second-hand copy of it.
FROM anchore/syft@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c AS syft
FROM anchore/grype@sha256:8a93fc48da96bd6ec5981279d099b69de11541dc68fdf222fb9161f8ff284af7 AS grype

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype

# Prove both tools run at build time, so a broken image never reaches a tester
# as "the scan found nothing".
RUN syft version -o text && grype version -o text

# The vulnerability database, baked in. grype updates it on first run by
# default, and this container has no network, so an image built without the
# database would start clean, fail its update silently, and report zero
# vulnerabilities for every package in every app. That failure looks exactly
# like good news, which is what makes it worth spending build time on.
ENV GRYPE_DB_CACHE_DIR=/opt/grype-db \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_VALIDATE_AGE=false
RUN mkdir -p /opt/grype-db \
 && GRYPE_DB_AUTO_UPDATE=true grype db update -vv \
 && grype db status

COPY analyze.py /opt/themob/analyze.py

RUN mkdir -p /scan /work \
 && chmod 0555 /opt/themob /work \
 && chmod 0444 /opt/themob/analyze.py \
 && chmod -R a+rX /opt/grype-db

USER 65534:65534
WORKDIR /work

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
