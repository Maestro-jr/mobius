"""Publishing a scan to S3 and registering the catalog in Zetaris (no network)."""
from __future__ import annotations

import csv
import io

import pytest

from themob.mobius.catalog import CATALOG
from themob.mobius.datalayer import DataLayerError, SqlResult
from themob.mobius.publish import (LOCATIONS, PublishError, S3Store, publish_obligations,
                                   publish_scan, to_csv)
from themob.mobius.zetaris_setup import (KEV_FIELDS, EPSS_FIELDS, epss_endpoint,
                                         feed_view, filestore_ddl, setup, typed_view)


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, ContentType):
        self.objects[(Bucket, Key)] = Body


def _tables():
    return {
        "mobius_scan.app": [{"run_id": "r1", "package": "com.acme.pay", "label": "Pay",
                             "version": "1.0", "platform": "android",
                             "permissions": "INTERNET", "libraries": "okhttp",
                             "sha256": "ab"}],
        "mobius_scan.findings": [{"run_id": "r1", "package": "com.acme.pay",
                                  "fingerprint": "f1", "title": 'say "hi"\nnext line',
                                  "severity": "high", "votes": 2, "confidence": 0.9,
                                  "advisory_id": "CVE-2021-0341"}],
        "mobius_scan.entities": [],
    }


def test_csv_is_one_line_per_row_without_double_quotes():
    data = to_csv(_tables()["mobius_scan.findings"],
                  list(CATALOG["mobius_scan.findings"]["columns"]))
    text = data.decode()
    assert text.count("\n") == 2
    assert '"' not in text
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["title"] == "say 'hi' next line"
    assert rows[0]["advisory_id"] == "CVE-2021-0341"


def test_publish_writes_one_file_per_table_per_run():
    store = S3Store("bucket", client=FakeS3())
    keys = publish_scan(_tables(), store, "r1")
    assert keys["mobius_scan.findings"] == "mobius/scan/findings/r1.csv"
    assert ("bucket", "mobius/scan/entities/r1.csv") in store.client.objects
    assert publish_obligations(store) == "mobius/intel/obligations/obligations.csv"
    assert store.uri("scan/findings") == "s3a://bucket/mobius/scan/findings/"


def test_store_from_env_names_what_is_missing(monkeypatch):
    for name in ("MOBIUS_S3_BUCKET", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(PublishError, match="MOBIUS_S3_BUCKET"):
        S3Store.from_env()
    monkeypatch.setenv("MOBIUS_S3_BUCKET", "b")
    with pytest.raises(PublishError, match="AWS_ACCESS_KEY_ID"):
        S3Store.from_env()


def test_ddl_shapes():
    ddl = filestore_ddl("scan_findings", "s3a://b/mobius/scan/findings/", "AK", "SK")
    assert ddl.startswith("CREATE LIGHTNING FILESTORE TABLE scan_findings FROM mobius_src "
                          "FORMAT CSV OPTIONS")
    assert 'awsAccessKeyId "AK"' in ddl and 'header "true"' in ddl
    view = typed_view("mobius_scan.findings", "scan_findings")
    assert view.startswith("CREATE OR REPLACE SCHEMASTORE VIEW findings WITH CONTAINER "
                           "mobius_scan AS SELECT")
    assert "CAST(votes AS INT) AS votes" in view
    assert "CAST(confidence AS DOUBLE) AS confidence" in view
    assert view.endswith("WHERE run_id IN (SELECT max(run_id) FROM mobius_src.scan_findings "
                         "GROUP BY package)")
    assert "WHERE" not in typed_view("mobius_intel.obligations", "obligations")


def test_epss_endpoint_is_scoped_to_the_apps_cves():
    url, raw = epss_endpoint(["cve-2021-0341", "GHSA-xxxx", "CVE-2020-1"])
    assert url.endswith("?cve=CVE-2020-1,CVE-2021-0341")
    assert raw.startswith("epss_") and len(raw) == 13
    assert epss_endpoint(["CVE-2020-1", "CVE-2021-0341"])[1] == raw
    assert "percentile-gt" in epss_endpoint([])[0]


def test_feed_view_handles_flat_and_nested_feeds():
    flat = feed_view("mobius_intel", "kev", "kev_feed",
                     ["cveID", "vendorProject", "product", "vulnerabilityName",
                      "dateAdded", "knownRansomwareCampaignUse", "requiredAction"],
                     KEV_FIELDS, "vulnerabilities")
    assert "cveID AS cve_id" in flat and "explode" not in flat
    nested = feed_view("mobius_intel", "epss", "epss_x", ["status", "total", "data"],
                       EPSS_FIELDS, "data")
    assert "LATERAL VIEW explode(data) x AS r" in nested
    assert "CAST(r.epss AS DOUBLE) AS epss" in nested
    with pytest.raises(DataLayerError, match="columns are: a, b"):
        feed_view("mobius_intel", "kev", "kev_feed", ["a", "b"], KEV_FIELDS,
                  "vulnerabilities")


class FakeZetaris:
    """Accepts DDL, answers probes and catalog queries, can refuse a statement."""

    def __init__(self, refuse=()):
        self.statements = []
        self.refuse = refuse

    def run(self, sql, *, limit=500):
        self.statements.append(sql)
        for needle, message in self.refuse:
            if needle in sql:
                raise DataLayerError(message)
        if sql.startswith("SELECT * FROM mobius_src.kev_feed"):
            return SqlResult(sql, ["catalogVersion", "vulnerabilities"], [["1", "[]"]],
                             "zq-1", "zetaris")
        if sql.startswith("SELECT * FROM mobius_src.epss_"):
            return SqlResult(sql, ["status", "data"], [["OK", "[]"]], "zq-2", "zetaris")
        return SqlResult(sql, ["x"], [[1]], "zq-3", "zetaris")


def test_setup_registers_everything_and_verifies_each_catalog_table():
    client = FakeZetaris(refuse=[("CREATE SCHEMASTORE CONTAINER mobius_scan",
                                  "container already exists")])
    report = setup(client, S3Store("bucket", client=FakeS3()), cves=["CVE-2021-0341"],
                   key_id="AKIDSECRET", secret="TOPSECRET")
    assert report.ok, report.lines()
    joined = "\n".join(client.statements)
    for _folder, raw in LOCATIONS.values():
        assert f"CREATE LIGHTNING FILESTORE TABLE {raw} FROM mobius_src" in joined
    assert "CREATE LIGHTNING REST TABLE kev_feed" in joined
    assert "explode(vulnerabilities)" in joined
    assert "api.first.org/data/v1/epss?cve=CVE-2021-0341" in joined
    for name in CATALOG:
        assert f"SELECT * FROM {name} LIMIT 3" in joined
    assert any("already registered" in line for line in report.lines())


def test_setup_failures_are_reported_without_credentials():
    client = FakeZetaris(refuse=[("FILESTORE TABLE scan_findings",
                                  "access denied for key AKIDSECRET / TOPSECRET")])
    report = setup(client, S3Store("bucket", client=FakeS3()), cves=[],
                   key_id="AKIDSECRET", secret="TOPSECRET")
    assert not report.ok
    text = "\n".join(report.lines())
    assert "FAIL file table mobius_src.scan_findings" in text
    assert "AKIDSECRET" not in text and "TOPSECRET" not in text


def test_secret_evidence_never_leaves_the_machine():
    from themob.mobius.catalog import redact_evidence
    key = "AIzaSyD" + "x" * 32
    assert redact_evidence(f"Google_API_Key: {key}", secret=True) == "Google_API_Key: AIza****xx"
    assert key not in redact_evidence(f"String k = \"{key}\";", secret=False)
    assert redact_evidence("uses HTTP to example.com", secret=False) == "uses HTTP to example.com"
