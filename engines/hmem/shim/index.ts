// mobius H-MEM shim: lets the official Meterless H-MEM conformance runner
// drive mobius's Python engine (themob/hmem/engine.py).
//
// The runner calls the engine synchronously, so each call runs
// `python -m themob.hmem.bridge` once. The engine persists all of its state
// (records, ledger, conflict queue, dream proposals, sleep backups) in a temp
// directory per HMEM instance, so separate processes behave as one instance.
// Records come back as write-through proxies: assigning a field (the runner
// sets `supersededBy` directly) updates the stored record.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const python = process.env.MOBIUS_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
const tempDirs: string[] = [];
process.on("exit", () => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

function bridge(dir: string, now: number, op: string, args: unknown): any {
  const res = spawnSync(python, ["-m", "themob.hmem.bridge"], {
    cwd: repoRoot,
    input: JSON.stringify({ dir, now, op, args }),
    encoding: "utf-8",
  });
  if (res.error) throw res.error;
  let out: { ok?: unknown; error?: string };
  try {
    out = JSON.parse(res.stdout);
  } catch {
    throw new Error(`H-MEM bridge returned no JSON for ${op}: ${res.stderr || res.stdout}`);
  }
  if (out.error) throw new Error(out.error);
  return out.ok;
}

export class HMEM {
  readonly store: any;
  readonly ledger: any;
  readonly sleep: any;
  readonly conflicts: any;
  readonly dreaming: any;
  private readonly call: (op: string, args?: unknown) => any;

  constructor(opts: { clock?: () => number } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mobius-hmem-"));
    tempDirs.push(dir);
    const clock = opts.clock ?? Date.now;
    this.call = (op, args = {}) => bridge(dir, clock(), op, args);
    const wrap = (record: any): any => {
      if (record === null || record === undefined) return undefined;
      return new Proxy(record, {
        set: (target, prop, value) => {
          target[prop as string] = value;
          this.call("store.update", { id: target.id, patch: { [prop as string]: value } });
          return true;
        },
      });
    };
    this.store = {
      get: (id: string) => wrap(this.call("store.get", { id })),
      all: () => (this.call("store.all") as any[]).map(wrap),
      update: (id: string, patch: object) => wrap(this.call("store.update", { id, patch })),
    };
    this.ledger = {
      history: (id: string) => this.call("ledger.history", { id }),
      stats: () => this.call("ledger.stats"),
    };
    this.sleep = {
      preview: () => this.call("sleep.preview"),
      execute: (preview?: unknown) => this.call("sleep.execute", { preview }),
    };
    this.conflicts = {
      scan: () => this.call("conflicts.scan"),
      autoResolve: (conflict: unknown) => this.call("conflicts.autoResolve", { conflict }),
    };
    this.dreaming = {
      dream: () => this.call("dreaming.dream"),
      approve: (id: string) => wrap(this.call("dreaming.approve", { id })),
    };
    (this as any).wrap = wrap;
  }

  add(input: Record<string, unknown>): any {
    return (this as any).wrap(this.call("add", input));
  }

  query(query: string, opts: Record<string, unknown> = {}): any {
    const result = this.call("query", { query, opts });
    result.memories = result.memories.map((m: any) => ({ ...m, memory: (this as any).wrap(m.memory) }));
    return result;
  }

  feedback(id: string, kind: string): void {
    this.call("feedback", { id, kind });
  }
}
