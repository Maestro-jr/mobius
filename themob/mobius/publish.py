"""Publish a scan where Zetaris can read it: CSV files in the cluster's S3 bucket.

A managed Zetaris cluster cannot read files on this laptop, so the scan tables
(:func:`themob.mobius.catalog.export_scan`) and the sector obligations go to
the Zetaris workspace bucket as CSV, one file per run per table:

    s3://<bucket>/mobius/scan/findings/<run_id>.csv
    s3://<bucket>/mobius/intel/obligations/obligations.csv

Each table is a folder, so a Zetaris file-store table over it reads every run
and the ``run_id`` column tells them apart. :mod:`themob.mobius.zetaris_setup`
registers those folders and the live KEV / EPSS feeds in Zetaris.

What goes up is the export, never the store: secret material is already
stripped by ``export_scan``, and the APK and workspace never leave the machine.
Cells are flattened to one line with no double quotes, so the CSV reads the
same in any parser without relying on Zetaris's quote and escape options.
"""
from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass, field

from .catalog import CATALOG, obligation_rows

PREFIX = "mobius"

# Where each catalog table lives under the bucket, and its raw table name in
# the Lightning database (see zetaris_setup).
LOCATIONS: dict[str, tuple[str, str]] = {
    "mobius_scan.app": ("scan/app", "scan_app"),
    "mobius_scan.findings": ("scan/findings", "scan_findings"),
    "mobius_scan.entities": ("scan/entities", "scan_entities"),
    "mobius_intel.obligations": ("intel/obligations", "obligations"),
    "mobius_web.assets": ("web/assets", "web_assets"),
    "mobius_web.findings": ("web/findings", "web_findings"),
}

# The file tables a given review publishes and registers. The intel feeds (KEV,
# EPSS) and obligations are registered alongside either, in zetaris_setup.
APP_TABLES = ("mobius_scan.app", "mobius_scan.findings", "mobius_scan.entities",
              "mobius_intel.obligations")
WEB_TABLES = ("mobius_web.assets", "mobius_web.findings", "mobius_intel.obligations")


class PublishError(RuntimeError):
    pass


def _cell(value) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").replace('"', "'")
    return text


def to_csv(rows: list[dict], columns: list[str]) -> bytes:
    """Rows as CSV with a header, in catalog column order."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(c)) for c in columns])
    return buffer.getvalue().encode("utf-8")


@dataclass
class S3Store:
    """The Zetaris workspace bucket, written with the operator's IAM key."""

    bucket: str
    region: str = ""
    client: object = None
    uploaded: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls, client=None) -> "S3Store":
        bucket = os.environ.get("MOBIUS_S3_BUCKET", "").strip()
        if not bucket:
            raise PublishError("MOBIUS_S3_BUCKET is not set: the WorkspaceS3Bucket "
                               "name from the Zetaris CloudFormation stack's Resources tab")
        region = os.environ.get("AWS_REGION", "").strip()
        if client is None:
            if not (os.environ.get("AWS_ACCESS_KEY_ID") and
                    os.environ.get("AWS_SECRET_ACCESS_KEY")):
                raise PublishError("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not "
                                   "set: create an access key for the mobius-s3 IAM user")
            import boto3                                   # only when publishing live
            client = boto3.client("s3", region_name=region or None)
        return cls(bucket, region, client)

    def uri(self, folder: str) -> str:
        """The folder as Zetaris addresses it."""
        return f"s3a://{self.bucket}/{PREFIX}/{folder}/"

    def put(self, folder: str, name: str, data: bytes) -> str:
        key = f"{PREFIX}/{folder}/{name}"
        try:
            self.client.put_object(Bucket=self.bucket, Key=key, Body=data,
                                   ContentType="text/csv")
        except Exception as exc:                           # boto3 raises many types
            raise PublishError(f"upload to s3://{self.bucket}/{key} failed: {exc}") from exc
        self.uploaded.append(key)
        return key


def publish_tables(tables: dict[str, list[dict]], store: S3Store, run_id: str) -> dict[str, str]:
    """Upload one run's catalog tables (app or web). Returns table -> object key."""
    keys = {}
    for name, rows in tables.items():
        folder, _raw = LOCATIONS[name]
        columns = list(CATALOG[name]["columns"])
        keys[name] = store.put(folder, f"{run_id}.csv", to_csv(rows, columns))
    return keys


def publish_scan(tables: dict[str, list[dict]], store: S3Store, run_id: str) -> dict[str, str]:
    return publish_tables(tables, store, run_id)


def publish_web(tables: dict[str, list[dict]], store: S3Store, run_id: str) -> dict[str, str]:
    return publish_tables(tables, store, run_id)


def publish_obligations(store: S3Store) -> str:
    """Upload the sector obligations map (one file, replaced each time)."""
    folder, _raw = LOCATIONS["mobius_intel.obligations"]
    columns = list(CATALOG["mobius_intel.obligations"]["columns"])
    return store.put(folder, "obligations.csv", to_csv(obligation_rows(), columns))
