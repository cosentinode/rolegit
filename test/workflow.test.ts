import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import test from "node:test";

import { createAuthServer } from "../src/auth-server.js";
import { initialize, lock, lockIfSessionExpired, login, protect, seal, unlock } from "../src/commands.js";
import { atomicWrite, materializationDigest } from "../src/files.js";
import { loadEnclist } from "../src/policy.js";
import {
  deleteSession,
  loadLease,
  loadSession,
  saveLease,
  saveSession,
  sessionId,
} from "../src/session.js";
import type { LocalSession, MaterializationLease, MaterializedFile, ServerPolicy } from "../src/types.js";

function localSession(server: string, id: number, token: string): LocalSession {
  return {
    server,
    token,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    user: { id, login: `user-${id}` },
  };
}

function leaseFor(
  root: string,
  session: LocalSession,
  paths: MaterializedFile[],
): MaterializationLease {
  return {
    version: 1,
    root: path.resolve(root),
    server: session.server,
    expiresAt: session.expiresAt,
    userId: session.user.id,
    sessionId: sessionId(session),
    paths,
  };
}

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

  await assert.rejects(() => unlock(root, []), /destination already exists/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=workflow-value\n");

  await rm(path.join(root, ".env"));
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });

  await unlock(root, []);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=workflow-value\n");
  if (process.platform !== "win32") {
    assert.equal((await stat(path.join(root, ".env"))).mode & 0o777, 0o600);
  }

  await writeFile(path.join(root, ".env"), "SECRET=updated-value\n");
  await seal(root, []);

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
  const session = localSession("http://127.0.0.1:8787", 101, "no-lease-token");
  await saveSession(session);

  await lock(root);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=user-owned\n");
  await assert.rejects(() => loadSession(session.server), /run `rolegit login` first/);
  await assert.rejects(() => unlock(root, []), /run `rolegit login` first/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=user-owned\n");
});

test("lock rejects a lease path outside the repository without deleting it", async () => {
  const parent = await mkdtemp(path.join(tmpdir(), "rolegit-lease-traversal-"));
  const root = path.join(parent, "repository");
  await mkdir(root);
  const home = path.join(parent, "home");
  process.env.ROLEGIT_HOME = home;
  const session = localSession("http://127.0.0.1:8787", 101, "traversal-token");
  await initialize(root, session.server);
  await saveSession(session);
  const outside = path.join(parent, "outside");
  await writeFile(outside, "keep me\n");
  await saveLease(leaseFor(root, session, []));
  const [leaseName] = await readdir(path.join(home, "leases"));
  await writeFile(
    path.join(home, "leases", leaseName!),
    `${JSON.stringify({
      version: 1,
      root: path.resolve(root),
      server: session.server,
      expiresAt: session.expiresAt,
      userId: session.user.id,
      sessionId: sessionId(session),
      paths: [{ path: "../outside", digest: materializationDigest(Buffer.from("keep me\n")) }],
    })}\n`,
  );

  await assert.rejects(() => lock(root), /lock completed with errors/);
  assert.equal(await readFile(outside, "utf8"), "keep me\n");
  await assert.rejects(() => loadSession(session.server), /run `rolegit login` first/);
});

test("lock preserves changed files but cleans other paths and the session", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-dirty-lock-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const session = localSession("http://127.0.0.1:8787", 101, "dirty-lock-token");
  const original = Buffer.from("original\n");
  const paths = ["dirty.env", "replaced.env", "clean.env"];
  for (const entry of paths) await writeFile(path.join(root, entry), original);
  await saveSession(session);
  await saveLease(leaseFor(root, session, paths.map((entry) => ({
    path: entry,
    digest: materializationDigest(original),
  }))));
  await writeFile(path.join(root, "dirty.env"), "unsaved edit\n");
  await rm(path.join(root, "replaced.env"));
  await mkdir(path.join(root, "replaced.env"));

  await assert.rejects(() => lock(root), /dirty\.env.*replaced\.env/);
  assert.equal(await readFile(path.join(root, "dirty.env"), "utf8"), "unsaved edit\n");
  assert.ok((await stat(path.join(root, "replaced.env"))).isDirectory());
  await assert.rejects(() => stat(path.join(root, "clean.env")), { code: "ENOENT" });
  await assert.rejects(() => loadSession(session.server), /run `rolegit login` first/);
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
});

test("expiry cleanup does not extend a lease across sessions or delete changed files", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-identity-expiry-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const alice = localSession("http://127.0.0.1:8787", 101, "alice-token");
  const bob = localSession(alice.server, 202, "bob-token");
  const original = Buffer.from("original\n");
  const paths = ["dirty.env", "replaced.env", "clean.env"];
  for (const entry of paths) await writeFile(path.join(root, entry), original);
  await saveLease(leaseFor(root, alice, paths.map((entry) => ({
    path: entry,
    digest: materializationDigest(original),
  }))));
  await assert.rejects(
    () => saveLease(leaseFor(root, bob, [])),
    /different session/,
  );
  await saveSession(alice);
  await assert.rejects(() => saveSession(bob), /run `rolegit lock` before logging in again/);
  await deleteSession(alice.server);
  await saveSession(bob);
  await writeFile(path.join(root, "dirty.env"), "unsaved edit\n");
  await rm(path.join(root, "replaced.env"));
  await mkdir(path.join(root, "replaced.env"));

  await assert.rejects(
    () => lockIfSessionExpired(root, new Date(Date.now() - 1_000).toISOString()),
    /dirty\.env.*replaced\.env/,
  );
  assert.equal(await readFile(path.join(root, "dirty.env"), "utf8"), "unsaved edit\n");
  assert.ok((await stat(path.join(root, "replaced.env"))).isDirectory());
  await assert.rejects(() => stat(path.join(root, "clean.env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  assert.equal((await loadSession(bob.server)).user.id, bob.user.id);
});
