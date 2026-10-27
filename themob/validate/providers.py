"""Read-only liveness probes, one per provider themob can recognise.

Each probe is a command an operator runs by hand, with the real credential they
read from the cited file. themob never fills the value in: it holds a digest and
a masked preview, not the secret, so ``<SECRET>`` stays a placeholder in every
command here. That is the point, not a limitation. The engine prepares the
check; the operator, who does hold the value, runs it.

Every probe is chosen to be **read-only**: it asks the provider "who am I" or
"is this key valid", never "do something". `aws sts get-caller-identity` reads
an identity; it creates nothing. A probe that could change state would make
validation an action against the account, which is exactly what an assessment
must not become.

Even so, a probe contacts the provider and can appear in its logs, so every one
carries that warning, and the gate in :mod:`themob.validate.gate` is what
authorises running it at all. The map is deliberately short: a provider with no
safe, generic, read-only check is left with no probe rather than a risky guess.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Probe:
    """How to check one provider's credential, read-only."""

    provider: str
    command: str                          # with <SECRET> (and <SECRET_ID>) placeholders
    live_when: str                        # how to read the result
    note: str = ""

    @property
    def needs_key_pair(self) -> bool:
        return "<SECRET_ID>" in self.command


# provider key -> probe. The provider key is what classify() returns.
PROBES: dict[str, Probe] = {
    "aws": Probe(
        provider="AWS",
        command=("AWS_ACCESS_KEY_ID=<SECRET_ID> AWS_SECRET_ACCESS_KEY=<SECRET> "
                 "aws sts get-caller-identity"),
        live_when="prints an account and ARN; an error means revoked or invalid",
        note="Needs both the access key id and the secret. Read-only: it "
             "identifies the caller and creates nothing."),
    "github": Probe(
        provider="GitHub",
        command=('curl -sS -o /dev/null -w "%{http_code}" '
                 '-H "Authorization: token <SECRET>" https://api.github.com/user'),
        live_when="200 means live, 401 means revoked",
        note="Reads the token's own user. Read-only."),
    "gitlab": Probe(
        provider="GitLab",
        command=('curl -sS -o /dev/null -w "%{http_code}" '
                 '-H "PRIVATE-TOKEN: <SECRET>" https://gitlab.com/api/v4/user'),
        live_when="200 means live, 401 means revoked",
        note="Reads the token's own user. Read-only."),
    "slack": Probe(
        provider="Slack",
        command=('curl -sS -H "Authorization: Bearer <SECRET>" '
                 "https://slack.com/api/auth.test"),
        live_when='"ok":true means live, "invalid_auth" means revoked',
        note="auth.test only reports who the token belongs to. Read-only."),
    "stripe": Probe(
        provider="Stripe",
        command="curl -sS https://api.stripe.com/v1/balance -u <SECRET>:",
        live_when="200 with a balance means live, 401 means revoked",
        note="Reads the account balance. Read-only, but this is a payments key: "
             "treat the result as sensitive."),
    "google": Probe(
        provider="Google / Firebase",
        command="",
        live_when="",
        note="No generic read-only probe: a Google API key authorises one "
             "specific API, so it must be checked against that API by hand, "
             "with a read-only call. Often the key is origin-restricted and "
             "benign, which is why it is not automatically flagged as live."),
}


def _hay(*parts) -> str:
    return " ".join(str(p).lower() for p in parts if p)


def classify(rule: str = "", tags=None, weakness_key: str = "",
             preview: str = "") -> str | None:
    """The provider a secret belongs to, from what the detector reported.

    None when nothing recognisable is present, which is the honest answer: a
    high-entropy string with no provider shape is not something to fire a probe
    at, and guessing a provider would fire the wrong one.
    """
    hay = _hay(rule, " ".join(tags or []), weakness_key)

    if "aws" in hay or preview.startswith(("AKIA", "ASIA")):
        return "aws"
    # "github", not a short "gh" token: "gh-" hides inside words like
    # "high-entropy" and would misfire the wrong probe.
    if "github" in hay or preview.startswith(("ghp_", "gho_", "ghs_", "ghr_",
                                              "github_pat_")):
        return "github"
    if "gitlab" in hay or preview.startswith("glpat-"):
        return "gitlab"
    if "slack" in hay or preview.startswith("xox"):
        return "slack"
    if "stripe" in hay or preview.startswith(("sk_live", "rk_live")):
        return "stripe"
    if any(t in hay for t in ("google", "gcp", "firebase")) or preview.startswith("AIza"):
        return "google"
    return None


def probe_for(provider: str | None) -> Probe | None:
    """The probe for a provider, or None. A provider with no command is skipped.

    Google is in the map for its explanatory note, but carries no command, so a
    caller asking for a runnable probe gets None and the note is surfaced
    separately.
    """
    if provider is None:
        return None
    probe = PROBES.get(provider)
    if probe is None or not probe.command:
        return None
    return probe
