import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import { initialize, protect } from "../src/commands.js";
import {
  atomicWrite,
  gitPathExistsInHistory,
  gitPathIsIgnored,
  gitPathIsTracked,
  materializationDigest,
  removeMaterializedFile,
} from "../src/files.js";
import { encryptedObjectPath, loadEnclist } from "../src/policy.js";

async function temporaryDirectory(context: TestContext, prefix: string): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), prefix));
  context.after(() => rm(root, { recursive: true, force: true }));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  return root;
}

test("failed atomic writes remove temporary files", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-atomic-");
  const destination = path.join(root, "destination");
  await mkdir(destination);

  await assert.rejects(() => atomicWrite(destination, Buffer.from("plaintext"), 0o600));
  assert.deepEqual(await readdir(root), ["destination"]);
});

test("protect refuses a secret that exists in Git history", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-history-");
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

test("protect refuses a symlinked gitignore", { skip: process.platform === "win32" }, async (context) => {
  const root = await temporaryDirectory(context, "rolegit-symlink-");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  const target = path.join(root, "sensitive-source");
  await writeFile(target, "LOCAL_SECRET\n");
  await symlink(target, path.join(root, ".gitignore"));

  await assert.rejects(() => protect(root, ".env"), /non-regular \.gitignore/);
});

test("protect rejects a case alias of an existing protected path", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-case-alias-");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  await protect(root, "Config.env");

  await assert.rejects(() => protect(root, "config.env"), /differs only by case/);
});

test("protect rejects tracked and historical path case aliases", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-git-case-alias-");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  execFileSync("git", ["config", "user.email", "test@rolegit.local"], { cwd: root });
  execFileSync("git", ["config", "user.name", "RoleGit Test"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  await writeFile(path.join(root, "Config.env"), "SECRET=tracked-case-alias\n");
  execFileSync("git", ["add", "Config.env"], { cwd: root });

  await assert.rejects(() => protect(root, "config.env"), /already tracked/);
  execFileSync("git", ["commit", "--quiet", "-m", "track case alias"], { cwd: root });
  execFileSync("git", ["rm", "--quiet", "Config.env"], { cwd: root });
  await assert.rejects(() => protect(root, "config.env"), /exists in Git history/);
});

test("protect rejects existing worktree aliases and ignores future portable aliases", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-worktree-case-alias-");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  await writeFile(path.join(root, "Existing.env"), "SECRET=existing-case-alias\n");
  await assert.rejects(() => protect(root, "existing.env"), /differs only by case from existing path/);

  await protect(root, "future.env");
  await writeFile(path.join(root, "Future.env"), "SECRET=future-case-alias\n");
  execFileSync("git", ["check-ignore", "--quiet", "--", "Future.env"], { cwd: root });
  execFileSync("git", ["add", "."], { cwd: root });
  assert.throws(() => execFileSync("git", ["ls-files", "--error-unmatch", "--", "Future.env"], {
    cwd: root,
    stdio: "ignore",
  }));
});

test("protect rejects portable RoleGit and Git metadata namespaces", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-metadata-paths-");
  const gitDirectory = path.join(root, "control");
  execFileSync("git", ["init", "--quiet", `--separate-git-dir=${gitDirectory}`, root]);
  await initialize(root, "http://127.0.0.1:8787");

  for (const metadataPath of [
    ".ENCLIST",
    ".enclist/child",
    ".ROLEGIT",
    ".rolegit/file",
    ".GITIGNORE",
    ".GIT",
    ".git/config",
    "CONTROL/config",
  ]) {
    await assert.rejects(() => protect(root, metadataPath), /metadata cannot be protected/);
  }
  const policy = await loadEnclist(root);
  policy.files["CONTROL/config"] = { object: encryptedObjectPath("CONTROL/config") };
  await writeFile(path.join(root, ".enclist"), `${JSON.stringify(policy)}\n`);
  await assert.rejects(() => loadEnclist(root), /Git metadata cannot be protected/);
});

test("protect excludes environment-selected in-worktree Git metadata", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-environment-git-dir-");
  const control = path.join(root, "control");
  execFileSync("git", ["init", "--bare", "--quiet", control]);
  const previousGitDirectory = process.env.GIT_DIR;
  const previousWorkTree = process.env.GIT_WORK_TREE;
  process.env.GIT_DIR = control;
  process.env.GIT_WORK_TREE = root;
  context.after(() => {
    if (previousGitDirectory === undefined) delete process.env.GIT_DIR;
    else process.env.GIT_DIR = previousGitDirectory;
    if (previousWorkTree === undefined) delete process.env.GIT_WORK_TREE;
    else process.env.GIT_WORK_TREE = previousWorkTree;
  });
  await initialize(root, "http://127.0.0.1:8787");

  await assert.rejects(() => protect(root, "CONTROL/config"), /metadata cannot be protected/);
});

test("prototype-named plaintext paths remain ordinary policy entries", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-prototype-names-");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  await protect(root, "__proto__");
  await protect(root, "constructor");

  assert.deepEqual(Object.keys((await loadEnclist(root)).files).sort(), ["__proto__", "constructor"]);
});

test("materialized-file removal refuses paths outside the repository", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-removal-");
  const root = path.join(parent, "repository");
  await mkdir(root);
  const outside = path.join(parent, "outside");
  await writeFile(outside, "keep me\n");

  await assert.rejects(
    () => removeMaterializedFile(root, {
      path: "../outside",
      digest: materializationDigest(Buffer.from("keep me\n")),
    }),
    /inside the repository/,
  );
  assert.equal(await readFile(outside, "utf8"), "keep me\n");
});

test("Git safety checks distinguish negative results from operational failures", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-git-errors-");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  assert.equal(gitPathIsTracked(root, ".env"), false);
  assert.equal(gitPathIsIgnored(root, ".env"), false);
  assert.equal(gitPathExistsInHistory(root, ".env"), false);
  await writeFile(path.join(root, ".gitignore"), "/Config.env\n");
  assert.equal(gitPathIsIgnored(root, "config.env"), true);

  await writeFile(path.join(root, ".git", "config"), "[broken\n");
  assert.throws(() => gitPathIsTracked(root, ".env"), /git ls-files failed/);
  assert.throws(() => gitPathIsIgnored(root, ".env"), /git check-ignore failed/);
  assert.throws(() => gitPathExistsInHistory(root, ".env"), /git log failed/);
});
