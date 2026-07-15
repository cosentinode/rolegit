import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { initialize, protect } from "../src/commands.js";
import { atomicWrite, removeMaterializedFile } from "../src/files.js";

test("failed atomic writes remove temporary files", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-atomic-"));
  const destination = path.join(root, "destination");
  execFileSync("mkdir", [destination]);

  await assert.rejects(() => atomicWrite(destination, Buffer.from("plaintext"), 0o600));
  assert.deepEqual(await readdir(root), ["destination"]);
});

test("protect refuses a secret that exists in Git history", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-history-"));
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  execFileSync("git", ["config", "user.email", "test@rolegit.local"], { cwd: root });
  execFileSync("git", ["config", "user.name", "RoleGit Test"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  await writeFile(path.join(root, ".env"), "SECRET=already-committed\n");
  execFileSync("git", ["add", ".env"], { cwd: root });
  execFileSync("git", ["commit", "--quiet", "-m", "commit secret"], { cwd: root });
  execFileSync("git", ["rm", "--quiet", "--cached", ".env"], { cwd: root });

  await assert.rejects(() => protect(root, ".env"), /exists in Git history/);
});

test("protect refuses a symlinked gitignore", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-symlink-"));
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  const target = path.join(root, "sensitive-source");
  await writeFile(target, "LOCAL_SECRET\n");
  await symlink(target, path.join(root, ".gitignore"));

  await assert.rejects(() => protect(root, ".env"), /non-regular \.gitignore/);
});

test("materialized-file removal refuses paths outside the repository", async () => {
  const parent = await mkdtemp(path.join(tmpdir(), "rolegit-removal-"));
  const root = path.join(parent, "repository");
  execFileSync("mkdir", [root]);
  const outside = path.join(parent, "outside");
  await writeFile(outside, "keep me\n");

  await assert.rejects(() => removeMaterializedFile(root, "../outside"), /inside the repository/);
  assert.equal(await readFile(outside, "utf8"), "keep me\n");
});
