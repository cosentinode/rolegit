import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import test from "node:test";

import { createAuthServer } from "../src/auth-server.js";
import { initialize, lock, login, protect, seal, unlock } from "../src/commands.js";
import { atomicWrite } from "../src/files.js";
import { loadEnclist } from "../src/policy.js";
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

  await lock(root);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });

  await login(authServer, 101);
  await unlock(root, []);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=workflow-value\n");
  assert.equal((await stat(path.join(root, ".env"))).mode & 0o777, 0o600);

  await rm(path.join(root, ".enclist"));
  await lock(root);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
});
