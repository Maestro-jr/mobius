"""Zetaris: the data layer every mobius agent reads through.

The agents never open the scan database. Everything they know about the app
(its findings, entities and dependencies) and about the world (CISA KEV, FIRST
EPSS, the sector obligations) is a table in Zetaris, and the Executor's one
tool is ``run_sql``. That puts Zetaris on the critical path: when it is not
reachable a live run stops and says so, it never falls back to local data.

:class:`ZetarisClient` follows the Participant Setup Guide's REST contract:
``POST {ZETARIS_REST_URL}/sql-editor/sqls/run`` with ``Authorization: Bearer
<API key>``, ``X-Org-ID`` and a fresh UUID ``X-Request-ID``, one statement per
request. Results come back as :class:`SqlResult` carrying the query id, which
is the citation a claim makes and the Critic re-checks.

:class:`SqliteDataLayer` runs the same SQL over SQLite for the hermetic tests.
It names itself as a test double in every result, and the live runner refuses
it.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib import error as urlerror
from urllib import request as urlrequest

# -- results -----------------------------------------------------------------


@dataclass
class SqlResult:
    sql: str
    columns: list[str]
    rows: list[list]
    query_id: str
    source: str                  # "zetaris" or "sqlite (test double)"
    elapsed_ms: int = 0
    truncated: bool = False

    def records(self) -> list[dict]:
        return [dict(zip(self.columns, row)) for row in self.rows]

    def preview(self, limit: int = 12, width: int = 1800) -> str:
        """A compact, model-friendly rendering of the result."""
        if not self.rows:
            return f"[{self.query_id}] 0 rows"
        lines = [f"[{self.query_id}] {len(self.rows)} rows; columns: "
                 + ", ".join(self.columns)]
        for row in self.rows[:limit]:
            lines.append(json.dumps(dict(zip(self.columns, row)), default=str))
        if len(self.rows) > limit:
            lines.append(f"... {len(self.rows) - limit} more rows")
        text = "\n".join(lines)
        return text if len(text) <= width else text[:width] + " ...(clipped)"


class DataLayerError(RuntimeError):
    def __init__(self, message: str, *, status: int = 0, sql: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.sql = sql


class DataLayer(Protocol):
    name: str
    live: bool

    def sql(self, statement: str, *, limit: int = 500) -> SqlResult: ...


# -- the read-only guard (model-written SQL) ----------------------------------

_WRITE_WORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|MERGE|GRANT|REVOKE|TRUNCATE|"
    r"UPSERT|RUN|MATERIALIZE|COMPILE|REFRESH|CACHE|UNCACHE|SET|USE|CALL|EXEC|"
    r"ATTACH|DETACH|PRAGMA|COPY|LOAD|REMOVE|REGISTER)\b", re.I)
_STRING = re.compile(r"'(?:[^']|'')*'")


def guard_read_only(statement: str) -> str:
    """One SELECT (or WITH ... SELECT), nothing that writes or registers."""
    sql = (statement or "").strip().rstrip(";").strip()
    if not sql:
        raise DataLayerError("empty SQL")
    bare = _STRING.sub("''", sql)
    if ";" in bare:
        raise DataLayerError("one statement per request (no ';' inside the SQL)")
    if not re.match(r"^(SELECT|WITH)\b", bare, re.I):
        raise DataLayerError("only SELECT / WITH queries are allowed for agents")
    match = _WRITE_WORDS.search(bare)
    if match:
        raise DataLayerError(f"read-only: {match.group(1).upper()} is not allowed")
    return sql


def tables_in(sql: str) -> list[str]:
    """``db.table`` names a statement reads, for the sponsor ledger."""
    from .catalog import CATALOG                   # an alias like mobius_scan.f is no table
    found = re.findall(r"\b(mobius_\w+\.\w+)\b", _STRING.sub("''", sql))
    return sorted({name for name in found if name in CATALOG})


# -- Zetaris over REST ---------------------------------------------------------

Transport = Callable[[str, str, dict, bytes | None, float], tuple[int, dict, bytes]]


def _urllib_transport(method, url, headers, body, timeout):
    req = urlrequest.Request(url, data=body, method=method, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=timeout) as response:   # noqa: S310
            return response.status, dict(response.headers), response.read()
    except urlerror.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read() or b""


_HINTS = {
    401: "the Zetaris API key is missing, wrong or expired: create a new one in "
         "Management > API Tokens and update ZETARIS_API_KEY",
    403: "this Zetaris user lacks permission for that object",
}


class ZetarisClient:
    def __init__(self, rest_url: str, api_key: str, org_id: str = "1", *,
                 transport: Transport | None = None, timeout: float = 120.0) -> None:
        if not rest_url:
            raise DataLayerError("ZETARIS_REST_URL is not set")
        if not api_key or api_key.startswith("your-"):
            raise DataLayerError("ZETARIS_API_KEY is not set: create one in the "
                                 "Zetaris UI under Management > API Tokens")
        self.rest_url = rest_url.rstrip("/")
        self._key = api_key
        self.org_id = str(org_id or "1")
        self._transport = transport or _urllib_transport
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"ZetarisClient({self.rest_url!r}, org={self.org_id})"

    @classmethod
    def from_env(cls, **kwargs) -> "ZetarisClient":
        return cls(os.environ.get("ZETARIS_REST_URL", ""),
                   os.environ.get("ZETARIS_API_KEY", ""),
                   os.environ.get("ZETARIS_ORG_ID", "1"), **kwargs)

    def run(self, statement: str, *, limit: int = 500) -> SqlResult:
        query_id = str(uuid.uuid4())
        headers = {"Authorization": f"Bearer {self._key}",
                   "X-Org-ID": self.org_id,
                   "X-Request-ID": str(uuid.uuid4()),
                   "Content-Type": "application/json",
                   "Accept": "application/json"}
        body = json.dumps({"queryId": query_id, "sql": statement,
                           "source": "SqlEditor", "limit": limit}).encode("utf-8")
        started = time.monotonic()
        try:
            status, _headers, raw = self._transport(
                "POST", self.rest_url + "/sql-editor/sqls/run", headers, body,
                self.timeout)
        except (urlerror.URLError, OSError, TimeoutError) as exc:
            raise DataLayerError(f"Zetaris is not reachable at {self.rest_url} "
                                 f"({exc})", sql=statement) from exc
        elapsed = int((time.monotonic() - started) * 1000)
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        if status >= 400:
            message = _error_text(payload) or f"HTTP {status}"
            hint = _HINTS.get(status)
            raise DataLayerError(f"Zetaris refused the query: {message}"
                                 + (f" ({hint})" if hint else ""),
                                 status=status, sql=statement)
        error = _error_text(payload) if isinstance(payload, dict) and \
            payload.get("status") in ("FAILED", "ERROR", "failed", "error") else ""
        if error:
            raise DataLayerError(f"Zetaris query failed: {error}", sql=statement)
        columns, rows = _parse_rows(payload)
        return SqlResult(statement, columns, rows, f"zq-{query_id[:8]}", "zetaris",
                         elapsed, truncated=len(rows) >= limit)


def _error_text(payload) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("error", "message", "msg", "errorMessage", "detail"):
        value = payload.get(key)
        if isinstance(value, dict):
            value = value.get("message") or json.dumps(value)
        if value:
            return str(value)[:500]
    return ""


def _parse_rows(payload) -> tuple[list[str], list[list]]:
    """Columns and rows from the SQL editor response, tolerant of its shapes."""
    if not isinstance(payload, dict):
        return [], []
    data = payload.get("data")
    if isinstance(data, dict):                     # {"data": {"columns", "rows"}}
        payload, data = data, data.get("rows") or data.get("data")
    data = data or []
    names = None
    for key in ("columns", "schema", "header", "headers", "fields", "columnNames"):
        value = payload.get(key)
        if isinstance(value, list) and value:
            names = [c.get("name") or c.get("columnName") or c.get("label")
                     if isinstance(c, dict) else str(c) for c in value]
            break
    if data and isinstance(data[0], dict):
        columns = names or list(data[0].keys())
        return columns, [[row.get(c) for c in columns] for row in data]
    rows = [list(r) if isinstance(r, (list, tuple)) else [r] for r in data]
    width = max((len(r) for r in rows), default=len(names or []))
    columns = names or [f"col{i}" for i in range(width)]
    return [str(c) for c in columns], rows


class ZetarisDataLayer:
    """What the agents hold: Zetaris, read-only."""

    name = "zetaris"
    live = True

    def __init__(self, client: ZetarisClient) -> None:
        self.client = client

    def sql(self, statement: str, *, limit: int = 500) -> SqlResult:
        return self.client.run(guard_read_only(statement), limit=limit)


# -- SQLite test double ------------------------------------------------------------


class SqliteDataLayer:
    """The same catalog in SQLite, for hermetic tests. Never used live."""

    name = "sqlite (test double)"
    live = False

    def __init__(self, tables: dict[str, list[dict]]) -> None:
        self._conn = sqlite3.connect(":memory:")
        schemas = sorted({name.split(".")[0] for name in tables})
        for schema in schemas:
            self._conn.execute(f"ATTACH DATABASE ':memory:' AS {schema}")
        for name, rows in tables.items():
            columns = list(rows[0].keys()) if rows else ["placeholder"]
            self._conn.execute(f"CREATE TABLE {name} ({', '.join(columns)})")
            if rows:
                marks = ", ".join("?" for _ in columns)
                self._conn.executemany(
                    f"INSERT INTO {name} VALUES ({marks})",
                    [[_cell(r.get(c)) for c in columns] for r in rows])
        self._seq = 0

    def sql(self, statement: str, *, limit: int = 500) -> SqlResult:
        statement = guard_read_only(statement)
        self._seq += 1
        try:
            cursor = self._conn.execute(statement)
        except sqlite3.Error as exc:
            raise DataLayerError(f"query failed: {exc}", sql=statement) from exc
        rows = [list(r) for r in cursor.fetchmany(limit)]
        columns = [d[0] for d in cursor.description or []]
        return SqlResult(statement, columns, rows, f"tq-{self._seq:03d}", self.name,
                         truncated=len(rows) >= limit)


def _cell(value):
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    if isinstance(value, bool):
        return int(value)
    return value
