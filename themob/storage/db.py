"""SQLite connection management and the migration runner.

Two things matter here and both are easy to get wrong:

* **Foreign keys are per-connection in SQLite.** ``PRAGMA foreign_keys = ON`` has
  to be issued on every connection or the ``ON DELETE CASCADE`` rules in the
  schema silently do nothing.
* **A connection may not cross threads.** The engine runs on a background
  ``QThread`` while the UI reads on the main thread, so :class:`Database` hands
  out a *thread-local* connection to the same file. WAL mode lets the reader and
  the writer proceed concurrently instead of blocking each other.
"""
from __future__ import annotations

import logging
import re
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# Migration files are named NNNN_description.sql; NNNN is the version.
_MIGRATION_RE = re.compile(r"^(\d+)_[A-Za-z0-9_\-]+\.sql$")

# Busy timeout (ms). The engine writes in bursts while the UI polls; without this
# a concurrent write raises "database is locked" instead of waiting.
_BUSY_TIMEOUT_MS = 5_000


class MigrationError(RuntimeError):
    """A migration file is malformed or failed to apply."""


class Database:
    """Owns one SQLite file and hands out per-thread connections to it."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._conns: list[sqlite3.Connection] = []   # every conn handed out, for close_all()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ connect

    @property
    def connection(self) -> sqlite3.Connection:
        """The calling thread's connection, opened on first use."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open()
            self._local.conn = conn
            with self._lock:
                self._conns.append(conn)
        return conn

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.path),
            timeout=_BUSY_TIMEOUT_MS / 1000.0,
            isolation_level=None,          # explicit transactions via `transaction()`
            detect_types=0,
        )
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute("PRAGMA foreign_keys = ON")
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            # NORMAL is safe under WAL (durability is lost only on OS/power loss,
            # not a process crash) and avoids an fsync per commit during the
            # write bursts an analysis run produces.
            cur.execute("PRAGMA synchronous = NORMAL")
        finally:
            cur.close()
        return conn

    def close(self) -> None:
        """Close this thread's connection."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            with self._lock:
                if conn in self._conns:
                    self._conns.remove(conn)
            conn.close()
            self._local.conn = None

    def close_all(self) -> None:
        """Close every connection handed out (call once at shutdown)."""
        with self._lock:
            conns, self._conns = self._conns, []
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:       # already closed / owning thread gone
                pass
        self._local = threading.local()

    # -------------------------------------------------------------- statements

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """Run a block in one transaction, rolling back on any exception."""
        conn = self.connection
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
        except BaseException:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            cur.close()

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        return self.connection.execute(sql, params)

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        cur = self.connection.execute(sql, params)
        try:
            return cur.fetchall()
        finally:
            cur.close()

    def query_one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        cur = self.connection.execute(sql, params)
        try:
            return cur.fetchone()
        finally:
            cur.close()

    # --------------------------------------------------------------- migrations

    def applied_versions(self) -> set[int]:
        row = self.query_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
        if row is None:
            return set()
        return {int(r["version"]) for r in self.query("SELECT version FROM schema_migrations")}

    def run_migrations(self, migrations_dir: Path | None = None) -> list[int]:
        """Apply every migration newer than the recorded version.

        Each file runs inside one transaction, so a failure leaves the schema at
        the previous version rather than half-migrated. Returns the versions
        applied by this call.
        """
        directory = Path(migrations_dir or MIGRATIONS_DIR)
        if not directory.is_dir():
            raise MigrationError(f"migrations directory not found: {directory}")

        pending = self._discover(directory)
        already = self.applied_versions()
        applied: list[int] = []

        for version, path in pending:
            if version in already:
                continue
            sql = path.read_text(encoding="utf-8")
            conn = self.connection
            # executescript() COMMITs any pending transaction before it runs and
            # performs no transaction control of its own, so a BEGIN issued from
            # Python around it is discarded and the migration would apply
            # statement by statement. The transaction has to be inside the
            # script. The version stamp goes in the same script, so a migration
            # can never be applied without being recorded. ``version`` comes from
            # the filename regex, so it is an int and safe to interpolate.
            script = (f"BEGIN;\n{sql}\n"
                      f"INSERT OR IGNORE INTO schema_migrations (version) "
                      f"VALUES ({version});\nCOMMIT;")
            try:
                conn.executescript(script)
            except sqlite3.Error as exc:
                if conn.in_transaction:
                    conn.rollback()
                raise MigrationError(f"migration {path.name} failed: {exc}") from exc
            logger.info("applied migration %s", path.name)
            applied.append(version)

        # PRAGMA foreign_keys is a no-op inside a transaction, so re-assert it
        # after the migration run in case a script toggled it.
        self.connection.execute("PRAGMA foreign_keys = ON")
        return applied

    @staticmethod
    def _discover(directory: Path) -> list[tuple[int, Path]]:
        found: dict[int, Path] = {}
        for path in sorted(directory.glob("*.sql")):
            match = _MIGRATION_RE.match(path.name)
            if match is None:
                raise MigrationError(
                    f"migration filename must be NNNN_description.sql: {path.name}")
            version = int(match.group(1))
            if version in found:
                raise MigrationError(
                    f"duplicate migration version {version}: "
                    f"{found[version].name} and {path.name}")
            found[version] = path
        return sorted(found.items())


def open_database(path: str | Path, *, migrate: bool = True) -> Database:
    """Open (creating if needed) the themob database and bring it up to date."""
    db = Database(path)
    if migrate:
        db.run_migrations()
    return db
