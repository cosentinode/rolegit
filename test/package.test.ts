import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("clean source package includes the CLI and referenced documentation", async (context) => {
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
  await symlink(path.join(projectRoot, "node_modules"), path.join(cleanRoot, "node_modules"), "dir");

  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const output = execFileSync(npm, ["pack", "--dry-run", "--json"], {
    cwd: cleanRoot,
    encoding: "utf8",
  });
  const result = JSON.parse(output) as Array<{ files: Array<{ path: string }> }>;
  const files = result[0]!.files.map((file) => file.path);
  assert.ok(files.includes("dist/src/cli.js"));
  assert.ok(files.includes("docs/security.md"));
  assert.ok(files.includes("server-policy.example.json"));
});
