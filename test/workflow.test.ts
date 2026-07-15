import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { createServer } from "node:http";
import test from "node:test";

import { createAuthServer } from "../src/auth-server.js";
import {
  expiryWatcherDelay,
  initialize,
  lock,
  lockIfSessionExpired,
  login,
  protect,
  seal,
  unlock,
} from "../src/commands.js";
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

function localSession(
  server: string,
  id: number,
  token: string,
  expiresAt = new Date(Date.now() + 60_000).toISOString(),
): LocalSession {
  return {
    server,
    token,
    expiresAt,
    user: { id, login: `user-${id}` },
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
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

  await login(root, authServer, 101);
  if (process.platform !== "win32") {
    const outside = await mkdtemp(path.join(tmpdir(), "rolegit-object-symlink-"));
    await mkdir(path.join(root, ".rolegit"), { recursive: true });
    await symlink(outside, path.join(root, ".rolegit", "vault"), "dir");
    await assert.rejects(() => seal(root, []), /symbolic-link path/);
    assert.deepEqual(await readdir(outside), []);
    await rm(path.join(root, ".rolegit", "vault"));
  }
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

  const boundary = Buffer.alloc(10 * 1024 * 1024, 0x41);
  await writeFile(path.join(root, ".env"), boundary);
  await seal(root, []);
  await lock(root, false);
  await unlock(root, []);
  assert.equal((await stat(path.join(root, ".env"))).size, boundary.length);

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

  await assert.rejects(() => lock(root), /remote logout failed/);
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

test("stale watcher leaves a replacement session lease and materialization intact", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-stale-watcher-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const original = Buffer.from("same materialization\n");
  const oldSession = localSession("http://127.0.0.1:8787", 101, "old-watcher-token");
  const newSession = localSession(oldSession.server, 101, "new-watcher-token");
  await writeFile(path.join(root, ".env"), original);
  await saveLease(leaseFor(root, oldSession, [{
    path: ".env",
    digest: materializationDigest(original),
  }]));
  const watcher = lockIfSessionExpired(root, new Date(Date.now() + 100).toISOString());
  await delay(50);
  await lock(root, false);
  await writeFile(path.join(root, ".env"), original);
  await saveLease(leaseFor(root, newSession, [{
    path: ".env",
    digest: materializationDigest(original),
  }]));

  await watcher;
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), original.toString("utf8"));
  assert.equal((await loadLease(root)).sessionId, sessionId(newSession));
});

test("unlock cleans an unchanged lease after offline session expiry", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-offline-expiry-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const session = localSession(
    "http://127.0.0.1:8787",
    101,
    "expired-token",
    new Date(Date.now() - 1_000).toISOString(),
  );
  const plaintext = Buffer.from("expired materialization\n");
  await initialize(root, session.server);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveSession(session);
  await saveLease(leaseFor(root, session, [{
    path: ".env",
    digest: materializationDigest(plaintext),
  }]));

  await assert.rejects(() => unlock(root, []), /RoleGit session expired/);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  await assert.rejects(() => loadSession(session.server), /run `rolegit login` first/);
});

test("concurrent same-session lease updates retain every materialized path", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-concurrent-lease-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const session = localSession("http://127.0.0.1:8787", 101, "concurrent-token");
  const first = { path: "first.env", digest: materializationDigest(Buffer.from("first\n")) };
  const second = { path: "second.env", digest: materializationDigest(Buffer.from("second\n")) };

  await Promise.all([
    saveLease(leaseFor(root, session, [first])),
    saveLease(leaseFor(root, session, [second])),
  ]);

  assert.deepEqual((await loadLease(root)).paths.map((file) => file.path).sort(), [
    "first.env",
    "second.env",
  ]);
});

test("concurrent lock and lease extension cannot orphan plaintext", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-concurrent-lock-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const session = localSession("http://127.0.0.1:8787", 101, "concurrent-lock-token");
  const original = Buffer.from("original\n");
  const added = Buffer.from("added\n");
  await writeFile(path.join(root, "original.env"), original);
  await writeFile(path.join(root, "added.env"), added);
  await saveLease(leaseFor(root, session, [{
    path: "original.env",
    digest: materializationDigest(original),
  }]));

  await Promise.all([
    lock(root, false),
    saveLease(leaseFor(root, session, [{
      path: "added.env",
      digest: materializationDigest(added),
    }])),
  ]);

  await assert.rejects(() => stat(path.join(root, "original.env")), { code: "ENOENT" });
  let addedExists = true;
  try {
    await stat(path.join(root, "added.env"));
  } catch (error) {
    assert.equal((error as NodeJS.ErrnoException).code, "ENOENT");
    addedExists = false;
  }
  if (addedExists) {
    assert.ok((await loadLease(root)).paths.some((file) => file.path === "added.env"));
  } else {
    await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  }
});

test("lock uses repository metadata after enclist removal", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-repository-session-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const session = localSession(url, 101, "repository-session-token");
  await initialize(root, url);
  await saveSession(session);
  await rm(path.join(root, ".enclist"));

  await lock(root);
  await assert.rejects(() => loadSession(url), /run `rolegit login` first/);
});

test("lock reports remote logout failure after deleting the local session", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-failed-logout-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const server = createServer((_request, response) => {
    response.writeHead(503, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "logout unavailable" }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const session = localSession(url, 101, "failed-logout-token");
  await initialize(root, url);
  await saveSession(session);

  await assert.rejects(() => lock(root), /remote logout failed: logout unavailable/);
  await assert.rejects(() => loadSession(url), /run `rolegit login` first/);
});

test("expiry watcher chunks delays above the Node timer limit", () => {
  const now = Date.now();
  const longExpiry = new Date(now + 30 * 24 * 60 * 60 * 1_000).toISOString();
  assert.equal(expiryWatcherDelay(longExpiry, now), 2_147_483_647);
  assert.throws(() => expiryWatcherDelay("not-a-date", now), /invalid expiry watcher expiration/);
});
