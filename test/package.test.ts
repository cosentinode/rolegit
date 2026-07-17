import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("package rebuild excludes stale output and includes required files", async (context) => {
  const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const cleanRoot = await mkdtemp(path.join(tmpdir(), "rolegit-package-"));
  context.after(() => rm(cleanRoot, { recursive: true, force: true }));
  for (const entry of [
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "README.md",
    "LICENSE",
    "server-policy.example.json",
    "src",
    "docs",
  ]) {
    await cp(path.join(projectRoot, entry), path.join(cleanRoot, entry), { recursive: true });
  }
  const npm = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  const npmArgs = (args: string[]) => process.platform === "win32"
    ? ["/d", "/s", "/c", "npm", ...args]
    : args;
  execFileSync(npm, npmArgs(["ci", "--ignore-scripts"]), { cwd: cleanRoot, stdio: "ignore" });
  await mkdir(path.join(cleanRoot, "dist", "src"), { recursive: true });
  await writeFile(path.join(cleanRoot, "dist", "src", "deleted-secret.js"), "stale output\n");
  const output = execFileSync(npm, npmArgs(["pack", "--dry-run", "--json"]), {
    cwd: cleanRoot,
    encoding: "utf8",
  });
  const result = JSON.parse(output) as Array<{ files: Array<{ path: string }> }>;
  const files = result[0]!.files.map((file) => file.path);
  assert.ok(files.includes("dist/src/cli.js"));
  for (const documentation of [
    "README.md",
    "docs/security.md",
    "docs/adr/0001-product-modes-and-trust-boundaries.md",
    "docs/adr/0002-branches-protocols-and-repository-ownership.md",
  ]) {
    assert.ok(files.includes(documentation), `package is missing ${documentation}`);
  }
  assert.ok(files.includes("server-policy.example.json"));
  assert.ok(!files.includes("dist/src/deleted-secret.js"));
});
