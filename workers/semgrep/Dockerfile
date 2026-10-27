# themob semgrep worker: insecure patterns in the decompiled code.
#
# Run by themob/sandbox/runner.py with --network none, --read-only,
# --cap-drop ALL and --user 65534:65534. Everything is baked in at build time.
#
# semgrep is LGPL-2.1 and invoked here as a subprocess, never imported, which
# is the same arms-length rule the other workers follow. The sandbox boundary
# and the licensing boundary are the same boundary.
#
# Built FROM the vendor's own image rather than `pip install semgrep`. A probe
# of the pip route could not find `semgrep-core`, the OCaml binary semgrep
# shells out to for actual matching: it is shipped as a platform wheel, and on
# any base without a matching wheel pip quietly installs the Python half alone.
# That produces a semgrep that starts, scans, and matches nothing. The vendor
# image has the pair already assembled and tested together.
#
# Pinned by digest, not just by tag: a tag is a moving pointer, and a scanner
# that silently changes version between builds is a scanner whose results
# cannot be compared across runs.
FROM semgrep/semgrep:1.90.0@sha256:7b625711ba9b6d1a543e308967b18c01b59932490a5536a06422666474bf6ee4

# No registry, no telemetry, no version check: all three reach for the network,
# and this container has none.
#
# HOME is load-bearing. semgrep creates a log directory under the user's home
# before it reads a single file, and uid 65534 has no passwd entry, so home
# resolves to "/" and the mkdir fails on the read-only root. semgrep then exits
# 1 with a traceback and no output, which is the same exit code it uses for
# "findings were found". That combination is what made a crashed scan look like
# a clean one.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_CONFIG_HOME=/tmp/.config \
    SEMGREP_SETTINGS_FILE=/tmp/.semgrep/settings.yml \
    SEMGREP_VERSION_CACHE_PATH=/tmp/.semgrep/cache

# Prove both halves are present at build time. semgrep without semgrep-core
# runs and finds nothing, which is the failure this check exists to catch,
# because it looks exactly like a clean result.
# The directories have to exist, not merely be named: semgrep's OCaml core
# reads XDG_CONFIG_HOME at startup and aborts with Sys_error if it is missing.
# analyze.py recreates them at run time too, because the sandbox mounts a fresh
# tmpfs over /tmp and anything made here is gone by then.
# World-writable because the self-test below, and the sandbox at run time, are
# uid 65534. Created by root here, these would otherwise be root-owned and
# semgrep would fail to write its settings file.
RUN mkdir -p /tmp/.config /tmp/.cache /tmp/.semgrep \
 && semgrep --version \
 && (command -v semgrep-core || python3 -c "import semgrep_core; print('semgrep_core module present')") \
 # semgrep writes a settings file on first run, and this ran as root, so it
 # lands root-owned and mode 600. The self-test below and the sandbox at run
 # time are uid 65534, which then cannot open it. Clear it and open the
 # directories up: nothing secret lives here, and /tmp is a fresh tmpfs anyway
 # once the sandbox mounts over it.
 && rm -f /tmp/.semgrep/settings.yml \
 && chmod -R 0777 /tmp/.config /tmp/.cache /tmp/.semgrep

# The rules, from knowledge/ at the repository root. Baked in because the
# container cannot reach the semgrep registry, so a rule that is not in the
# image is a rule that never runs.
COPY rules /opt/themob/rules
COPY analyze.py /opt/themob/analyze.py

# Fail the build if the rule pack did not make it in. An image with no rules
# scans clean for every app, which is the worst way to be wrong.
RUN test -n "$(find /opt/themob/rules -name '*.yml' -o -name '*.yaml')" \
 || (echo "no semgrep rules were copied into the image" && exit 1)

RUN mkdir -p /scan /work \
 && chmod -R a+rX /opt/themob \
 && chmod 0555 /work

USER 65534:65534
WORKDIR /work

# Prove the rules MATCH, as the unprivileged user the sandbox actually runs.
# Every earlier check here ran as root, which is why they all passed while the
# real scan died on a permission error. This one compiles the rules, runs them
# over a sample carrying both weaknesses, and fails the build unless both fire.
# A rule pack that loads but matches nothing is the exact failure this stage
# exists to avoid, and it is invisible from the outside.
RUN mkdir -p /tmp/.config /tmp/.cache /tmp/.semgrep /tmp/selftest \
 && printf '%s\n' \
      'import java.security.MessageDigest;' \
      'import javax.crypto.Cipher;' \
      'public class SelfTest {' \
      '    public static Cipher c() throws Exception {' \
      '        return Cipher.getInstance("AES/ECB/PKCS5Padding");' \
      '    }' \
      '    public static MessageDigest d() throws Exception {' \
      '        return MessageDigest.getInstance("MD5");' \
      '    }' \
      '}' > /tmp/selftest/SelfTest.java \
 && { semgrep --config /opt/themob/rules --json --quiet --metrics=off \
        --no-git-ignore /tmp/selftest > /tmp/selftest/out.json 2>/tmp/selftest/err.txt \
      || true; } \
 && { test -s /tmp/selftest/out.json \
      || { echo "semgrep produced no output during the self-test:"; \
           cat /tmp/selftest/err.txt; exit 1; }; } \
 && python3 -c "import json,sys; d=json.load(open('/tmp/selftest/out.json')); \
ids={r.get('check_id','') for r in d.get('results',[])}; \
want=('themob-weak-cipher-mode','themob-weak-hash'); \
missing=[r for r in want if not any(i.endswith(r) for i in ids)]; \
sys.exit('rules did not match %s (matched: %s)' % (missing, sorted(ids))) if missing else None" \
 && rm -rf /tmp/selftest

ENTRYPOINT ["python3", "/opt/themob/analyze.py"]
