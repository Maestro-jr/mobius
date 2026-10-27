"""Register mobius's sources in Zetaris and expose them under the catalog names.

Two layers, both Zetaris:

1. **Raw sources** in one Lightning database, ``mobius_src``:
   * ``scan_app`` / ``scan_findings`` / ``scan_entities`` / ``obligations``:
     file-store tables over the CSV folders :mod:`themob.mobius.publish`
     writes to the workspace bucket.
   * ``kev_feed``: a REST table over the live CISA Known Exploited
     Vulnerabilities feed.
   * ``epss_<hash>``: a REST table over the FIRST EPSS API for exactly the CVEs
     this app's dependencies carry (the endpoint takes the CVE list).
2. **Views** in SchemaStore containers ``mobius_scan`` and ``mobius_intel``,
   named and typed as :data:`themob.mobius.catalog.CATALOG` describes them, so
   the Executor's SQL never depends on how a feed happens to be shaped.

The KEV and EPSS views are written after probing the registered table: a REST
table may arrive flat (one row per vulnerability) or as one row holding the
JSON array, and the view flattens whichever it is.

Statements that create something that already exists are reported and skipped,
so ``setup`` is safe to run again after every scan.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .catalog import CATALOG
from .datalayer import DataLayerError
from .publish import LOCATIONS

SOURCE_DB = "mobius_src"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"

_INT_COLUMNS = {"votes", "exported", "depth", "exploited"}
_REAL_COLUMNS = {"confidence"}
# ``risk`` is a 0..10 score in the app findings, but a severity word on web
# assets; only the numeric one is cast.
_REAL_BY_TABLE = {"mobius_scan.findings": {"risk"}}
_EXISTS = re.compile(r"already exist|duplicate|exists", re.I)


@dataclass
class Step:
    name: str
    ok: bool
    note: str = ""


@dataclass
class SetupReport:
    steps: list[Step] = field(default_factory=list)

    def add(self, name: str, ok: bool, note: str = "") -> None:
        self.steps.append(Step(name, ok, note))

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)

    def lines(self) -> list[str]:
        return [f"{'PASS' if s.ok else 'FAIL'} {s.name}" + (f": {s.note}" if s.note else "")
                for s in self.steps]


def _q(value: str) -> str:
    return '"' + str(value).replace('"', "") + '"'


def _options(pairs: dict[str, str]) -> str:
    return ",\n  ".join(f"{k} {_q(v)}" for k, v in pairs.items())


def filestore_ddl(raw: str, uri: str, key_id: str = "", secret: str = "") -> str:
    options = {"path": uri, "header": "true", "delimiter": ","}
    if key_id and secret:
        options["awsAccessKeyId"] = key_id
        options["awsSecretAccessKey"] = secret
    return (f"CREATE LIGHTNING FILESTORE TABLE {raw} FROM {SOURCE_DB} FORMAT CSV "
            f"OPTIONS (\n  {_options(options)}\n)")


def rest_ddl(raw: str, endpoint: str) -> str:
    request = {"endpoint": endpoint, "method": "GET", "http_encoding": "URLENCODED",
               "response_type": "JSON", "insecure_ssl": "false"}
    return (f"CREATE LIGHTNING REST TABLE {raw} FROM {SOURCE_DB} REQUEST (\n  "
            f"{_options(request)}\n) HEADER () BODY ()")


def epss_endpoint(cves: list[str]) -> tuple[str, str]:
    """The EPSS URL for these CVEs and a stable raw table name for that set."""
    wanted = sorted({c.upper() for c in cves if c.upper().startswith("CVE-")})
    if wanted:
        url = f"{EPSS_URL}?cve={','.join(wanted[:100])}"
    else:                     # no CVE in this app: keep the table, show the riskiest
        url = f"{EPSS_URL}?percentile-gt=0.995&limit=100"
    digest = hashlib.sha256(url.encode()).hexdigest()[:8]
    return url, f"epss_{digest}"


def typed_view(name: str, raw: str) -> str:
    """A view exposing a CSV table under its catalog name, numbers cast."""
    container, view = name.split(".")
    columns = CATALOG[name]["columns"]
    real = _REAL_COLUMNS | _REAL_BY_TABLE.get(name, set())
    cols = []
    for column in columns:
        if column in _INT_COLUMNS:
            cols.append(f"CAST({column} AS INT) AS {column}")
        elif column in real:
            cols.append(f"CAST({column} AS DOUBLE) AS {column}")
        else:
            cols.append(column)
    latest = ""
    if "run_id" in columns:                       # every publish adds a run; serve the newest
        subject = "package" if "package" in columns else "target"
        latest = (f" WHERE run_id IN (SELECT max(run_id) FROM {SOURCE_DB}.{raw} "
                  f"GROUP BY {subject})")
    return (f"CREATE OR REPLACE SCHEMASTORE VIEW {view} WITH CONTAINER {container} AS "
            f"SELECT {', '.join(cols)} FROM {SOURCE_DB}.{raw}{latest}")


KEV_FIELDS = {"cve_id": "cveID", "vendor": "vendorProject", "product": "product",
              "name": "vulnerabilityName", "date_added": "dateAdded",
              "ransomware": "knownRansomwareCampaignUse", "action": "requiredAction"}
EPSS_FIELDS = {"cve": "cve", "epss": "epss", "percentile": "percentile", "date": "date"}


def feed_view(container: str, view: str, raw: str, columns: list[str],
              fields: dict[str, str], array: str) -> str:
    """Flatten a REST table whichever shape it arrived in.

    ``columns`` are the registered table's columns. If the record fields are
    already columns the view renames them; if the records sit in one array
    column (``array``) the view explodes it first.
    """
    present = {c.lower(): c for c in columns}
    numeric = {"epss", "percentile"}
    if all(src.lower() in present for src in fields.values()):
        picks = [(f"CAST({present[src.lower()]} AS DOUBLE)" if out in numeric
                  else present[src.lower()]) + f" AS {out}" for out, src in fields.items()]
        source = f"{SOURCE_DB}.{raw}"
    elif array.lower() in present:
        picks = [(f"CAST(r.{src} AS DOUBLE)" if out in numeric else f"r.{src}")
                 + f" AS {out}" for out, src in fields.items()]
        source = (f"{SOURCE_DB}.{raw} LATERAL VIEW explode({present[array.lower()]}) "
                  f"x AS r")
    else:
        raise DataLayerError(f"{raw} has neither the record fields nor a "
                             f"'{array}' array; its columns are: {', '.join(columns)}")
    return (f"CREATE OR REPLACE SCHEMASTORE VIEW {view} WITH CONTAINER {container} AS "
            f"SELECT {', '.join(picks)} FROM {source}")


_HIDDEN: list[str] = []        # credentials that must never reach a printed note


def _scrub(text: str) -> str:
    for secret in _HIDDEN:
        if secret:
            text = text.replace(secret, "****")
    return text


def _run(client, report: SetupReport, name: str, sql: str, *, may_exist: bool = False):
    try:
        client.run(sql, limit=5)
        report.add(name, True)
        return True
    except DataLayerError as exc:
        message = _scrub(str(exc))
        if may_exist and _EXISTS.search(message):
            report.add(name, True, "already registered")
            return True
        report.add(name, False, message[:300])
        return False


def setup(client, store, *, cves: list[str], key_id: str = "", secret: str = "",
          tables: tuple[str, ...] | None = None) -> SetupReport:
    """Register the chosen file tables plus the live feeds, and verify each.

    ``tables`` is the catalog file tables this review published (app or web); the
    others keep whatever registration they already had and are verified only when
    they resolve. The KEV/EPSS feeds are always (re)registered.
    """
    report = SetupReport()
    _HIDDEN[:] = [key_id, secret]
    wanted = set(tables) if tables is not None else set(LOCATIONS)
    containers = sorted({name.split(".")[0] for name in wanted} | {"mobius_intel"})
    _run(client, report, f"lightning database {SOURCE_DB}",
         f"CREATE LIGHTNING DATABASE {SOURCE_DB} DESCRIBE BY "
         f"\"mobius sources\"",
         may_exist=True)
    for container in containers:
        _run(client, report, f"schemastore container {container}",
             f"CREATE SCHEMASTORE CONTAINER {container}", may_exist=True)

    for name, (folder, raw) in LOCATIONS.items():
        if name not in wanted:
            continue
        if _run(client, report, f"file table {SOURCE_DB}.{raw}",
                filestore_ddl(raw, store.uri(folder), key_id, secret), may_exist=True):
            _run(client, report, f"view {name}", typed_view(name, raw))

    feeds = [("mobius_intel", "kev", "kev_feed", KEV_URL, KEV_FIELDS, "vulnerabilities")]
    epss_url, epss_raw = epss_endpoint(cves)
    feeds.append(("mobius_intel", "epss", epss_raw, epss_url, EPSS_FIELDS, "data"))
    for container, view, raw, url, fields, array in feeds:
        if not _run(client, report, f"REST table {SOURCE_DB}.{raw}", rest_ddl(raw, url),
                    may_exist=True):
            continue
        try:
            probe = client.run(f"SELECT * FROM {SOURCE_DB}.{raw} LIMIT 1", limit=1)
            sql = feed_view(container, view, raw, probe.columns, fields, array)
        except DataLayerError as exc:
            report.add(f"view {container}.{view}", False, str(exc)[:300])
            continue
        _run(client, report, f"view {container}.{view}", sql)

    from .catalog import OPTIONAL
    for name in CATALOG:
        try:
            result = client.run(f"SELECT * FROM {name} LIMIT 3", limit=3)
            report.add(f"query {name}", True, f"{len(result.rows)} row(s), columns "
                       f"{', '.join(result.columns)[:160]}")
        except DataLayerError as exc:
            if name in OPTIONAL and name not in wanted:
                report.add(f"query {name}", True, "optional, not published this run")
            else:
                report.add(f"query {name}", False, str(exc)[:300])
    return report
