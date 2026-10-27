"""mobius command line.

    python -m themob.mobius doctor            check Nightshift, Zetaris and H-MEM
    python -m themob.mobius models            list Nightshift routes (pick lanes)
    python -m themob.mobius publish [--project P]
                                              app scan -> S3 -> Zetaris tables + views
    python -m themob.mobius webscan DOMAIN     website recon (TOPRECON) -> S3 -> Zetaris
    python -m themob.mobius run --target DOMAIN   a live website review
    python -m themob.mobius run --package P   a live run: Zetaris + H-MEM + Nemotron
        [--sector S] [--no-memory] [--no-advisories] [--out DIR]

A live run has no fallback: if Nightshift or Zetaris is not reachable it stops
and names the fix. ``.env`` in the working directory is read first (values
already in the environment win).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def load_env(path: Path = Path(".env")) -> None:
    """Minimal .env reader: KEY=VALUE lines, # comments, no expansion."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if key.strip() and value:
            os.environ.setdefault(key.strip(), value)


def _ok(flag: bool) -> str:
    return "PASS" if flag else "FAIL"


def cmd_doctor(_args) -> int:
    from ..assist.meterless import MeterlessClient, MeterlessError
    from ..hmem.scan_memory import ScanMemory, default_memory_dir
    from .datalayer import DataLayerError, ZetarisClient
    from .catalog import CATALOG
    failures = 0

    try:
        client = MeterlessClient.from_env()
        state = client.state()
        print(f"{_ok(state == 'online')} Nightshift runtime at {client.base_url}: {state}")
        failures += state != "online"
        if state == "online":
            ids = [m.get("id") for m in client.models()]
            print(f"     routes: {', '.join(i for i in ids if i)}")
            for role in ("PLANNER", "EXECUTOR", "CRITIC"):
                route = os.environ.get(f"MOBIUS_{role}_MODEL") or client.model
                try:
                    _text, receipt = client.with_route(route, role.lower()).chat(
                        [{"role": "user", "content": "Reply with the single word: ready"}],
                        max_tokens=256)  # reasoning lanes spend tokens thinking first
                    nemo = receipt.nemotron
                    print(f"{_ok(nemo)} {role.lower():<8} lane {route} answered with "
                          f"{receipt.model}" + ("" if nemo else " (not Nemotron: pin a "
                                                "Nemotron lane for the NVIDIA prize)"))
                    failures += not nemo
                except MeterlessError as exc:
                    print(f"FAIL {role.lower():<8} lane {route}: {exc}")
                    failures += 1
    except MeterlessError as exc:
        print(f"FAIL Nightshift: {exc}")
        failures += 1

    try:
        zetaris = ZetarisClient.from_env()
        one = zetaris.run("SELECT 1 AS one")
        print(f"{_ok(bool(one.rows))} Zetaris SQL at {zetaris.rest_url}: SELECT 1 -> "
              f"{one.rows[:1]}")
        from .catalog import OPTIONAL
        for table in CATALOG:
            try:
                zetaris.run(f"SELECT * FROM {table} LIMIT 1", limit=1)
                print(f"PASS   {table}")
            except DataLayerError as exc:
                if table in OPTIONAL:
                    print(f"SKIP   {table}: not published yet (web review, optional)")
                else:
                    print(f"FAIL   {table}: {str(exc)[:160]}")
                    failures += 1
    except DataLayerError as exc:
        print(f"FAIL Zetaris: {exc}")
        failures += 1

    directory = default_memory_dir()
    memory = ScanMemory(directory)
    print(f"PASS H-MEM memory at {directory}: {len(memory.hmem.store.all())} memories, "
          f"{len(memory.hmem.ledger.all())} ledger entries")
    print("\nAll checks passed." if not failures else f"\n{failures} check(s) failed.")
    return 1 if failures else 0


def cmd_models(_args) -> int:
    from ..assist.meterless import MeterlessClient
    for model in MeterlessClient.from_env().models():
        print(model.get("id"), "", {k: v for k, v in model.items() if k != "id"})
    return 0


def cmd_publish(args) -> int:
    """Export a themob scan to S3 and register it (plus KEV/EPSS) in Zetaris."""
    import time
    from ..cli import _open, _resolve_project
    from .catalog import export_scan
    from .datalayer import DataLayerError, ZetarisClient
    from .publish import (APP_TABLES, PublishError, S3Store, publish_obligations,
                          publish_scan)
    from .zetaris_setup import setup

    _root, database, repos, _audit = _open(args)
    try:
        project, error = _resolve_project(repos, args.project)
        if project is None:
            print(f"FAIL {error}")
            return 2
        scan_id = f"scan-{time.strftime('%Y%m%d-%H%M%S')}-{project.id[:6]}"
        tables = export_scan(repos, project.id, scan_id)
    finally:
        database.close()
    package = tables["mobius_scan.app"][0]["package"]
    findings = tables["mobius_scan.findings"]
    cves = sorted({f["advisory_id"] for f in findings
                   if f["advisory_id"].startswith("CVE-")})
    print(f"Exported {package} ({project.name}): {len(findings)} findings, "
          f"{len(tables['mobius_scan.entities'])} entities, {len(cves)} CVEs. "
          f"Run id {scan_id}.")
    try:
        store = S3Store.from_env()
        for name, key in publish_scan(tables, store, scan_id).items():
            print(f"PASS uploaded {name} -> s3://{store.bucket}/{key}")
        print(f"PASS uploaded obligations -> s3://{store.bucket}/"
              f"{publish_obligations(store)}")
    except PublishError as exc:
        print(f"FAIL {exc}")
        return 1
    if args.skip_setup:
        return 0
    try:
        client = ZetarisClient.from_env()
    except DataLayerError as exc:
        print(f"FAIL Zetaris: {exc}")
        return 1
    report = setup(client, store, cves=cves, tables=APP_TABLES,
                   key_id=os.environ.get("AWS_ACCESS_KEY_ID", ""),
                   secret=os.environ.get("AWS_SECRET_ACCESS_KEY", ""))
    print("\n".join(report.lines()))
    if report.ok:
        print(f"\nZetaris is serving the catalog. Next: python -m themob.mobius run "
              f"--package {package}")
    return 0 if report.ok else 1


def cmd_webscan(args) -> int:
    """Recon a website with TOPRECON, publish it to S3, register it in Zetaris."""
    import time
    from .datalayer import DataLayerError, ZetarisClient
    from .publish import (WEB_TABLES, PublishError, S3Store, publish_obligations,
                          publish_web)
    from .webrecon import WebReconError, normalize, run_toprecon
    from .zetaris_setup import setup

    target = args.target.strip().lower()
    run_id = f"web-{time.strftime('%Y%m%d-%H%M%S')}-{target[:16]}"
    print(f"Running TOPRECON over {target} (passive{', active' if args.active else ''}"
          f"{', dorks' if args.dorks else ''}). This can take a few minutes.")
    try:
        graph = run_toprecon(target, active=args.active, dorks=args.dorks,
                             depth=args.depth if args.depth >= 0 else None)
    except WebReconError as exc:
        print(f"FAIL TOPRECON: {exc}")
        return 1
    scan = normalize(graph, target, run_id)
    sev = {}
    for f in scan.findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    print(f"Mapped {len(scan.assets)} assets and {len(scan.findings)} findings "
          f"({', '.join(f'{n} {s}' for s, n in sev.items()) or 'none'}), "
          f"{len(scan.secrets_local)} secrets. Run id {run_id}.")
    if scan.secrets_local:
        local = _write_web_secrets(run_id, scan.secrets_local)
        print(f"     {len(scan.secrets_local)} exposed secret(s) kept locally for "
              f"rotation: {local} (redacted in the cloud copy)")
    cves = sorted({f["advisory_id"] for f in scan.findings
                   if f["advisory_id"].startswith("CVE-")})
    try:
        store = S3Store.from_env()
        for name, key in publish_web(scan.tables(), store, run_id).items():
            print(f"PASS uploaded {name} -> s3://{store.bucket}/{key}")
        publish_obligations(store)
    except PublishError as exc:
        print(f"FAIL {exc}")
        return 1
    if args.skip_setup:
        return 0
    try:
        client = ZetarisClient.from_env()
    except DataLayerError as exc:
        print(f"FAIL Zetaris: {exc}")
        return 1
    report = setup(client, store, cves=cves, tables=WEB_TABLES,
                   key_id=os.environ.get("AWS_ACCESS_KEY_ID", ""),
                   secret=os.environ.get("AWS_SECRET_ACCESS_KEY", ""))
    print("\n".join(report.lines()))
    if report.ok:
        print(f"\nZetaris is serving the web surface. Next: python -m themob.mobius "
              f"run --target {target}")
    return 0 if report.ok else 1


def _write_web_secrets(run_id: str, secrets: list[dict]) -> str:
    """Write discovered secrets to the local run dir only, never the cloud."""
    import json
    from ..storage.workspace import default_root
    out = default_root() / "runs" / run_id
    out.mkdir(parents=True, exist_ok=True)
    path = out / "exposed_secrets.json"
    path.write_text(json.dumps(secrets, indent=2), encoding="utf-8")
    return str(path)


def cmd_run(args) -> int:
    from ..assist.meterless import MeterlessClient
    from ..hmem.scan_memory import ScanMemory
    from .agents import Lanes, RoleModels
    from .datalayer import ZetarisClient, ZetarisDataLayer
    from .loop import Orchestrator, RunOptions, new_run_id, write_run
    from .trace import RunTrace, format_event, format_ledger

    run_id = new_run_id()
    trace = RunTrace(run_id)
    trace.subscribe(lambda e: print(format_event(e), flush=True))
    client = MeterlessClient.from_env()
    if client.state() != "online":
        print(f"Nightshift is not online at {client.base_url}; run `doctor`.")
        return 2
    models = RoleModels(client, Lanes.from_env(client.model), trace)
    data = ZetarisDataLayer(ZetarisClient.from_env())
    memory = None if args.no_memory else ScanMemory()
    target = getattr(args, "target", "") or ""
    kind = "web" if target else "app"
    options = RunOptions(use_memory=not args.no_memory,
                         use_advisories=not args.no_advisories,
                         sector=args.sector or None, kind=kind, target=target.lower())
    subject = target.lower() if kind == "web" else args.package
    result = Orchestrator(data, models, memory, trace, options).run(subject)
    from ..storage.workspace import default_root
    out = Path(args.out) if args.out else default_root() / "runs" / run_id
    write_run(result, out)
    print()
    print(format_ledger(trace.ledger()))
    print(f"\nVerdict: {result.verdict['verdict']}. Report: {out / 'report.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Nightshift descriptions carry non-ASCII text; a cp1252 console would crash.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    load_env()
    parser = argparse.ArgumentParser(prog="mobius", description=__doc__.split("\n")[0])
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("doctor", help="check Nightshift, Zetaris and H-MEM").set_defaults(
        func=cmd_doctor)
    subs.add_parser("models", help="list Nightshift routes").set_defaults(func=cmd_models)
    pub = subs.add_parser("publish", help="send a themob scan to S3 and register "
                                         "it, KEV and EPSS in Zetaris")
    pub.add_argument("--project", default="", help="themob project id, prefix or "
                                                   "name (default: the latest)")
    pub.add_argument("--home", default="", help="themob home (default ~/.themob)")
    pub.add_argument("--skip-setup", action="store_true",
                     help="upload only, do not register tables in Zetaris")
    pub.set_defaults(func=cmd_publish)
    web = subs.add_parser("webscan", help="recon a website with TOPRECON, publish it "
                                         "to S3 and register it in Zetaris")
    web.add_argument("target", help="a domain, e.g. example.com")
    web.add_argument("--active", action="store_true",
                     help="allow active modules that touch the target (authorized only)")
    web.add_argument("--dorks", action="store_true", help="run Google dork discovery")
    web.add_argument("--depth", type=int, default=-1, help="max pivot depth (0 to 4)")
    web.add_argument("--skip-setup", action="store_true",
                     help="upload only, do not register tables in Zetaris")
    web.set_defaults(func=cmd_webscan)
    run = subs.add_parser("run", help="a live evidence-backed review")
    run.add_argument("--package", default="", help="app id in mobius_scan.app")
    run.add_argument("--target", default="", help="a domain in mobius_web.assets "
                                                 "(a website review instead of an app)")
    run.add_argument("--sector", default="", help="confirm the sector (saved to memory)")
    run.add_argument("--no-memory", action="store_true", help="ablation: H-MEM off")
    run.add_argument("--no-advisories", action="store_true",
                     help="ablation: KEV/EPSS off")
    run.add_argument("--out", default="", help="output directory")
    run.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
