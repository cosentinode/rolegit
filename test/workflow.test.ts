import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import test from "node:test";

import { createAuthServer } from "../src/auth-server.js";
import { initialize, lock, login, protect, seal, unlock } from "../src/commands.js";
import { atomicWrite } from "../src/files.js";
import { loadEnclist } from "../src/policy.js";
import { saveLease } from "../src/session.js";
import type { ServerPolicy } from "../src/types.js";

test("protect, seal, lock, and unlock workflow", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-workflow-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  execFileSync("git", ["init", "--quiet"], { cwd: root });

  const serverPolicy: ServerPolicy = {
    version: 1,
    sessionMinutes: 60,
    keyId: "workflow-key",
    developmentUsers: [{ id: 101, login: "workflow-user" }],
    vaults: {},
  };
  const server = createAuthServer({
    policy: serverPolicy,
    keyEncryptionKey: randomBytes(32),
    allowDevelopmentAuth: true,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const authServer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  await initialize(root, authServer);
  await atomicWrite(path.join(root, ".env"), Buffer.from("SECRET=workflow-value\n"), 0o600);
  await protect(root, ".env");
  const enclist = await loadEnclist(root);
  serverPolicy.vaults[enclist.vaultId] = {
    repository: "local/workflow",
    files: { ".env": { users: [101], teams: [] } },
  };

  await login(authServer, 101);
  await seal(root, []);
  const objectPath = enclist.files[".env"]!.object;
  const encrypted = await readFile(path.join(root, objectPath), "utf8");
  assert.doesNotMatch(encrypted, /workflow-value/);

  await rm(path.join(root, ".env"));
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });

  await login(authServer, 101);
  await unlock(root, []);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=workflow-value\n");
  assert.equal((await stat(path.join(root, ".env"))).mode & 0o777, 0o600);

  await rm(path.join(root, ".enclist"));
  await lock(root);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
});

test("lock and failed unlock preserve plaintext without a lease", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-no-lease-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  await writeFile(path.join(root, ".env"), "SECRET=user-owned\n");
  await protect(root, ".env");

  await assert.rejects(() => lock(root, false), { code: "ENOENT" });
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=user-owned\n");
  await assert.rejects(() => unlock(root, []), /run `rolegit login` first/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=user-owned\n");
});

test("lock rejects a lease path outside the repository without deleting it", async () => {
  const parent = await mkdtemp(path.join(tmpdir(), "rolegit-lease-traversal-"));
  const root = path.join(parent, "repository");
  execFileSync("mkdir", [root]);
  const home = path.join(parent, "home");
  process.env.ROLEGIT_HOME = home;
  const outside = path.join(parent, "outside");
  await writeFile(outside, "keep me\n");
  await saveLease({
    root: path.resolve(root),
    server: "http://127.0.0.1:8787",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    paths: [],
  });
  const [leaseName] = await readdir(path.join(home, "leases"));
  await writeFile(
    path.join(home, "leases", leaseName!),
    `${JSON.stringify({
      root: path.resolve(root),
      server: "http://127.0.0.1:8787",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      paths: ["../outside"],
    })}\n`,
  );

  await assert.rejects(() => lock(root, false), /inside the repository/);
  assert.equal(await readFile(outside, "utf8"), "keep me\n");
});
