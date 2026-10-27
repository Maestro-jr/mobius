"""What counts as a sink, and why each one matters.

A sink is a place where a value stops being an internal detail and becomes a
consequence: it leaves the device, gets written where another app can read it,
lands in a log, or is used as a key. A hardcoded string that reaches one of
these is a different finding from a hardcoded string that reaches nothing, even
though a scanner reports both identically.

The patterns are matched against **decompiled Java text**, so they are written
against what jadx emits: fully qualified names get shortened to the class, and
Kotlin lowers to method calls with recognisable names. Each entry is a plain
substring rather than a regular expression wherever it can be, because a
substring cannot backtrack and this runs over attacker-controlled text.

This list is deliberately short. A sink catalogue that tries to be exhaustive
becomes a list nobody can audit, and a wrong entry here does not fail loudly:
it quietly moves confidence on findings a tester then trusts.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sink:
    """One API whose use makes a value consequential."""

    pattern: str            # substring, matched case-sensitively
    category: str
    note: str


# Ordered by how strongly reaching one supports "this really is a credential".
SINKS: tuple[Sink, ...] = (
    # --- it leaves the device -------------------------------------------------
    Sink("setRequestProperty", "network", "sent as an HTTP header"),
    Sink("addHeader", "network", "sent as an HTTP header"),
    Sink("header(", "network", "sent as an HTTP header"),
    Sink("openConnection", "network", "used to open a connection"),
    Sink("HttpURLConnection", "network", "used with an HTTP connection"),
    Sink("OkHttpClient", "network", "used with an OkHttp client"),
    Sink("Retrofit", "network", "used with a Retrofit client"),
    Sink(".newCall(", "network", "used in an HTTP call"),
    Sink("loadUrl", "webview", "loaded into a WebView"),
    Sink("evaluateJavascript", "webview", "evaluated as JavaScript"),
    Sink("addJavascriptInterface", "webview", "exposed to WebView JavaScript"),

    # --- it is used as a key --------------------------------------------------
    Sink("SecretKeySpec", "crypto", "used as a cryptographic key"),
    Sink("Cipher.getInstance", "crypto", "used with a cipher"),
    Sink("Mac.getInstance", "crypto", "used with a MAC"),
    Sink("MessageDigest.getInstance", "crypto", "used with a digest"),

    # --- it is written where something else can read it -----------------------
    Sink("putString", "storage", "written to shared preferences"),
    Sink("openFileOutput", "storage", "written to a file"),
    Sink("FileOutputStream", "storage", "written to a file"),
    Sink("execSQL", "storage", "used in a SQL statement"),
    Sink("rawQuery", "storage", "used in a SQL query"),

    # --- it is announced ------------------------------------------------------
    # Logging is a real leak on a shared device and in a crash report, but it is
    # weaker evidence that the value is a live credential than sending it is.
    Sink("Log.d(", "log", "written to the log"),
    Sink("Log.e(", "log", "written to the log"),
    Sink("Log.i(", "log", "written to the log"),
    Sink("Log.v(", "log", "written to the log"),
    Sink("Log.w(", "log", "written to the log"),
    Sink("System.out.print", "log", "printed to stdout"),

    # --- it crosses to another app -------------------------------------------
    Sink("putExtra", "ipc", "put into an Intent extra"),
    Sink("sendBroadcast", "ipc", "sent in a broadcast"),
)

# How much reaching each category supports the reporting tool's claim. Sending a
# value as an Authorization header says far more about it being a credential
# than logging it does, and a model that treated them alike would be easy to
# argue with.
CATEGORY_WEIGHT: dict[str, float] = {
    "network": 0.75,
    "crypto": 0.7,
    "webview": 0.65,
    "storage": 0.5,
    "ipc": 0.5,
    "log": 0.35,
}

_DEFAULT_WEIGHT = 0.4


def weight(category: str) -> float:
    return CATEGORY_WEIGHT.get(category, _DEFAULT_WEIGHT)


def find(line: str) -> Sink | None:
    """The first sink this line reaches, or None.

    First rather than all: a line calling two sinks is one use site, and
    counting it twice would let formatting decide a confidence.
    """
    for sink in SINKS:
        if sink.pattern in line:
            return sink
    return None
