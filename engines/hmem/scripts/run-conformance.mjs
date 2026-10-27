// Runs conformance/runner.ts with HMEM_IMPL pointing at the mobius shim.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const impl = path.join(root, "shim", "index.ts").split(path.sep).join("/");
const res = spawnSync("npx", ["tsx", path.join(root, "conformance", "runner.ts")], {
  cwd: root,
  stdio: "inherit",
  shell: process.platform === "win32",
  env: { ...process.env, HMEM_IMPL: impl },
});
process.exit(res.status ?? 2);
