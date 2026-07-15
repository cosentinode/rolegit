import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
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
import { loadEnclist, saveEnclist } from "../src/policy.js";
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

  const originalFetch = globalThis.fetch;
  context.after(() => {
    globalThis.fetch = originalFetch;
  });
  let releaseUnwrap!: () => void;
  const unwrapReleased = new Promise<void>((resolve) => {
    releaseUnwrap = resolve;
  });
  let markUnwrapStarted!: () => void;
  const unwrapStarted = new Promise<void>((resolve) => {
    markUnwrapStarted = resolve;
  });
  globalThis.fetch = async (input, init) => {
    if (new URL(String(input)).pathname === "/v1/keys/unwrap") {
      markUnwrapStarted();
      await unwrapReleased;
    }
    return originalFetch(input, init);
  };
  const concurrentUnlock = unlock(root, []);
  await unwrapStarted;
  let lockFinished = false;
  const concurrentLock = lock(root).then(() => {
    lockFinished = true;
  });
  await delay(25);
  assert.equal(lockFinished, false);
  releaseUnwrap();
  await Promise.all([concurrentUnlock, concurrentLock]);
  globalThis.fetch = originalFetch;
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });

  await login(root, authServer, 101);
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
  await saveSession(root, session);

  await assert.rejects(() => lock(root), /remote logout failed/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "SECRET=user-owned\n");
  await assert.rejects(() => loadSession(root, session.server), /run `rolegit login` first/);
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
  await saveSession(root, session);
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
  await assert.rejects(() => loadSession(root, session.server), /run `rolegit login` first/);
});

test("lock preserves changed files but cleans other paths and the session", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-dirty-lock-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const session = localSession("http://127.0.0.1:8787", 101, "dirty-lock-token");
  const original = Buffer.from("original\n");
  const paths = ["dirty.env", "replaced.env", "clean.env"];
  for (const entry of paths) await writeFile(path.join(root, entry), original);
  await saveSession(root, session);
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
  await assert.rejects(() => loadSession(root, session.server), /run `rolegit login` first/);
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
  await saveSession(root, alice);
  await assert.rejects(() => saveSession(root, bob), /run `rolegit lock` before logging in again/);
  await deleteSession(root, alice.server);
  await saveSession(root, bob);
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
  assert.equal((await loadSession(root, bob.server)).user.id, bob.user.id);
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
  await saveSession(root, session);
  await saveLease(leaseFor(root, session, [{
    path: ".env",
    digest: materializationDigest(plaintext),
  }]));

  await assert.rejects(() => unlock(root, []), /RoleGit session expired/);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  await assert.rejects(() => loadSession(root, session.server), /run `rolegit login` first/);
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
  await saveSession(root, session);
  await rm(path.join(root, ".enclist"));

  await lock(root);
  await assert.rejects(() => loadSession(root, url), /run `rolegit login` first/);
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
  await saveSession(root, session);

  await assert.rejects(() => lock(root), /remote logout failed: logout unavailable/);
  await assert.rejects(() => loadSession(root, url), /run `rolegit login` first/);
});

test("expiry watcher chunks delays above the Node timer limit", () => {
  const now = Date.now();
  const longExpiry = new Date(now + 30 * 24 * 60 * 60 * 1_000).toISOString();
  assert.equal(expiryWatcherDelay(longExpiry, now), 2_147_483_647);
  assert.throws(() => expiryWatcherDelay("not-a-date", now), /invalid expiry watcher expiration/);
});

test("a killed lock owner is reclaimed without blocking cleanup", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-killed-lock-"));
  const home = path.join(root, ".test-home");
  process.env.ROLEGIT_HOME = home;
  const moduleUrl = new URL("../src/session.js", import.meta.url).href;
  const script = `
    import { withRepositoryLock } from ${JSON.stringify(moduleUrl)};
    await withRepositoryLock(process.env.CHILD_ROOT, async () => {
      process.stdout.write("locked");
      await new Promise(() => setInterval(() => undefined, 1_000));
    });
  `;
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: { ...process.env, CHILD_ROOT: root, ROLEGIT_HOME: home },
    stdio: ["ignore", "pipe", "inherit"],
  });
  context.after(() => child.kill("SIGKILL"));
  await once(child.stdout!, "data");
  child.kill("SIGKILL");
  await once(child, "exit");

  const session = localSession("http://127.0.0.1:8787", 101, "reclaimed-lock-token");
  await saveLease(leaseFor(root, session, []));
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
});

test("concurrent logins keep one local session and revoke the losing token", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-concurrent-login-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  let issued = 0;
  const revoked: string[] = [];
  const server = createServer((request, response) => {
    if (request.url === "/v1/auth/development") {
      issued += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        session: {
          token: `login-token-${issued}`,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          user: { id: 101, login: "concurrent-user" },
        },
      }));
      return;
    }
    revoked.push(request.headers.authorization ?? "");
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const results = await Promise.allSettled([
    login(root, url, 101),
    login(root, url, 101),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);
  assert.equal(revoked.length, 1);
  const winner = await loadSession(root, url);
  assert.notEqual(revoked[0], `Bearer ${winner.token}`);
});

test("expired-session cleanup cannot delete a concurrent replacement", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-session-transition-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  const server = "http://127.0.0.1:8787";
  const expired = localSession(server, 101, "expired-race-token", new Date(Date.now() - 1_000).toISOString());
  const replacement = localSession(server, 101, "replacement-race-token");
  await saveSession(root, expired);

  await Promise.allSettled([
    loadSession(root, server),
    saveSession(root, replacement),
  ]);
  assert.equal((await loadSession(root, server)).token, replacement.token);
});

test("login updates an association, and later checkout changes cannot redirect lock", async (context) => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-server-change-"));
  process.env.ROLEGIT_HOME = path.join(root, ".test-home");
  let firstLogouts = 0;
  let secondLogouts = 0;
  const first = createServer((_request, response) => {
    firstLogouts += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  const second = createServer((request, response) => {
    if (request.url === "/v1/auth/development") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        session: {
          token: "second-server-token",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          user: { id: 101, login: "server-change-user" },
        },
      }));
      return;
    }
    secondLogouts += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  first.listen(0, "127.0.0.1");
  second.listen(0, "127.0.0.1");
  await Promise.all([once(first, "listening"), once(second, "listening")]);
  context.after(() => first.close());
  context.after(() => second.close());
  const firstUrl = `http://127.0.0.1:${(first.address() as AddressInfo).port}`;
  const secondUrl = `http://127.0.0.1:${(second.address() as AddressInfo).port}`;
  await initialize(root, firstUrl);
  const policy = await loadEnclist(root);
  policy.authServer = secondUrl;
  await saveEnclist(root, policy);
  await login(root, secondUrl, 101);
  policy.authServer = firstUrl;
  await saveEnclist(root, policy);

  await lock(root);
  assert.equal(firstLogouts, 0);
  assert.equal(secondLogouts, 1);
  await assert.rejects(() => loadSession(root, secondUrl), /run `rolegit login` first/);
});

test("repository-scoped lock leaves another repository session and lease intact", async (context) => {
  const parent = await mkdtemp(path.join(tmpdir(), "rolegit-repository-sessions-"));
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  const firstRoot = path.join(parent, "first");
  const secondRoot = path.join(parent, "second");
  await Promise.all([mkdir(firstRoot), mkdir(secondRoot)]);
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const firstSession = localSession(url, 101, "first-repository-token");
  const secondSession = localSession(url, 101, "second-repository-token");
  const plaintext = Buffer.from("shared server\n");
  await Promise.all([
    initialize(firstRoot, url),
    initialize(secondRoot, url),
    writeFile(path.join(firstRoot, ".env"), plaintext),
    writeFile(path.join(secondRoot, ".env"), plaintext),
  ]);
  await Promise.all([
    saveSession(firstRoot, firstSession),
    saveSession(secondRoot, secondSession),
    saveLease(leaseFor(firstRoot, firstSession, [{ path: ".env", digest: materializationDigest(plaintext) }])),
    saveLease(leaseFor(secondRoot, secondSession, [{ path: ".env", digest: materializationDigest(plaintext) }])),
  ]);

  await lock(firstRoot);
  await assert.rejects(() => stat(path.join(firstRoot, ".env")), { code: "ENOENT" });
  assert.equal(await readFile(path.join(secondRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadSession(secondRoot, url)).token, secondSession.token);
  assert.equal((await loadLease(secondRoot)).sessionId, sessionId(secondSession));
});

test("repository session access migrates legacy server-scoped credentials", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rolegit-session-migration-"));
  const home = path.join(root, ".test-home");
  process.env.ROLEGIT_HOME = home;
  const session = localSession("http://127.0.0.1:8787", 101, "legacy-session-token");
  const legacyId = createHash("sha256").update(session.server).digest("hex");
  const legacyPath = path.join(home, "sessions", `${legacyId}.json`);
  await mkdir(path.dirname(legacyPath), { recursive: true });
  await writeFile(legacyPath, `${JSON.stringify(session)}\n`);

  assert.equal((await loadSession(root, session.server)).token, session.token);
  await assert.rejects(() => stat(legacyPath), { code: "ENOENT" });
});
