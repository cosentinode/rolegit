import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { rmSync, writeFileSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";

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
  loadExpiryCleanupError,
  loadRepositoryServers,
  loadSession,
  repositoryId,
  repositoryInstance,
  saveLease,
  saveRepositoryServer,
  saveSession,
  sessionId,
  withRepositoryLock,
} from "../src/session.js";
import type { LocalSession, MaterializationLease, MaterializedFile, ServerPolicy } from "../src/types.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

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

async function runCli(
  root: string,
  home: string,
  args: string[],
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(process.execPath, [path.join(projectRoot, "dist/src/cli.js"), ...args], {
    cwd: root,
    env: { ...process.env, ROLEGIT_HOME: home },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { code, stdout, stderr };
}

async function temporaryDirectory(context: TestContext, prefix: string): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), prefix));
  context.after(() => rm(root, { recursive: true, force: true }));
  context.after(() => rm(`${root}-home`, { recursive: true, force: true }));
  return root;
}

function leaseFor(
  root: string,
  session: LocalSession,
  paths: MaterializedFile[],
  generation = randomUUID(),
): MaterializationLease {
  return {
    version: 1,
    repositoryId: repositoryId(root),
    repositoryInstance: repositoryInstance(root),
    generation,
    root: path.resolve(root),
    server: session.server,
    expiresAt: session.expiresAt,
    userId: session.user.id,
    sessionId: sessionId(session),
    paths,
  };
}

function operationLockPath(root: string, home: string): string {
  const id = createHash("sha256").update(repositoryId(root)).digest("hex");
  return path.join(home, "leases", `${id}.json.operation.lock`);
}

function instanceLockPath(root: string, home: string): string {
  const instance = repositoryInstance(root);
  const id = createHash("sha256").update(`${instance.device}\0${instance.inode}`).digest("hex");
  return path.join(home, "repositories", "instances", `${id}.lock`);
}

function spawnTestProcess(
  context: TestContext,
  script: string,
  environment: Record<string, string>,
): {
  ready: Promise<void>;
  exit: Promise<number | null>;
  child: ReturnType<typeof spawn>;
  stderr: () => string;
} {
  const child = spawn(process.execPath, ["--input-type=module", "--eval", script], {
    env: { ...process.env, ...environment },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const exit = new Promise<number | null>((resolve) => {
    const timeout = setTimeout(() => {
      stderr += "\nchild process timed out";
      child.kill("SIGKILL");
      resolve(null);
    }, 30_000);
    const finish = (code: number | null) => {
      clearTimeout(timeout);
      resolve(code);
    };
    child.once("error", () => finish(null));
    child.once("exit", (code) => finish(code));
  });
  const ready = new Promise<void>((resolve, reject) => {
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      child.stdout!.off("data", onReady);
      child.off("error", onError);
      child.off("exit", onExit);
      if (error) {
        child.kill("SIGKILL");
        reject(error);
      } else {
        resolve();
      }
    };
    const onReady = () => finish();
    const onError = (error: Error) => finish(new Error(`child process failed: ${error.message}\n${stderr}`));
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => finish(new Error(
      `child exited before readiness (code ${code ?? "none"}, signal ${signal ?? "none"})\n${stderr}`,
    ));
    const timeout = setTimeout(() => finish(new Error(`timed out waiting for child readiness\n${stderr}`)), 10_000);
    child.stdout!.once("data", onReady);
    child.once("error", onError);
    child.once("exit", onExit);
  });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await Promise.race([closed, delay(1_000)]);
    }
  });
  return { child, ready, exit, stderr: () => stderr };
}

test("child readiness reports early failures without hanging", async (context) => {
  const failed = spawnTestProcess(context, `
    console.error("fixture failed before readiness");
    process.exitCode = 2;
  `, {});
  await assert.rejects(failed.ready, /fixture failed before readiness/);
  assert.equal(await failed.exit, 2);
});

test("protect, seal, lock, and unlock workflow", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-workflow-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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
    const outside = await temporaryDirectory(context, "rolegit-object-symlink-");
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

test("workflow output does not expose secret canaries", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-output-canary-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const plaintextCanary = "PLAINTEXT_CANARY_ISSUE_6";
  const kekCanary = "KEK_CANARY_ISSUE_6";
  const serverPolicy: ServerPolicy = {
    version: 1,
    sessionMinutes: 60,
    keyId: "output-canary-key",
    developmentUsers: [{ id: 101, login: "output-canary-user" }],
    vaults: {},
  };
  const server = createAuthServer({
    policy: serverPolicy,
    keyEncryptionKey: Buffer.from(kekCanary.padEnd(32, "!")),
    allowDevelopmentAuth: true,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const authServer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const output: string[] = [];
  const tokens: string[] = [];
  const command = async (args: string[], expectedCode = 0) => {
    const result = await runCli(root, home, args);
    output.push(result.stdout, result.stderr);
    assert.equal(result.code, expectedCode, `${args.join(" ")}\n${result.stderr}`);
    return result;
  };

  await command(["init", "--server", authServer]);
  await writeFile(path.join(root, ".env"), `${plaintextCanary}=value\n`);
  await command(["protect", ".env"]);
  const enclist = await loadEnclist(root);
  serverPolicy.vaults[enclist.vaultId] = {
    repository: "local/output-canary",
    files: { ".env": { users: [101], teams: [] } },
  };

  await command(["login", "--development-user", "101"]);
  tokens.push((await loadSession(root, authServer)).token);
  await command(["seal"]);
  await command(["lock"]);
  await rm(path.join(root, ".env"));
  await command(["login", "--development-user", "101"]);
  const unlockSession = await loadSession(root, authServer);
  tokens.push(unlockSession.token);
  await saveSession(root, { ...unlockSession, expiresAt: new Date(Date.now() + 8_000).toISOString() });
  await command(["unlock"]);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), `${plaintextCanary}=value\n`);

  const existingDestination = await command(["unlock"], 1);
  assert.match(existingDestination.stderr, /destination already exists/);
  await command(["lock"]);
  await command(["login", "--development-user", "101"]);
  tokens.push((await loadSession(root, authServer)).token);
  serverPolicy.vaults[enclist.vaultId]!.files[".env"] = { users: [], teams: [] };
  const deniedByServer = await command(["unlock"], 1);
  assert.match(deniedByServer.stderr, /user is not authorized for this file/);

  await command(["lock"]);
  serverPolicy.vaults[enclist.vaultId]!.files[".env"] = { users: [101], teams: [] };
  await command(["login", "--development-user", "101"]);
  const expiringSession = await loadSession(root, authServer);
  tokens.push(expiringSession.token);
  await saveSession(root, { ...expiringSession, expiresAt: new Date(Date.now() + 1_500).toISOString() });
  await command(["unlock"]);
  const expiryDeadline = Date.now() + 8_000;
  while (Date.now() < expiryDeadline) {
    try {
      await stat(path.join(root, ".env"));
      await delay(100);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") break;
      throw error;
    }
  }
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });

  const renderedOutput = output.join("\n");
  assert.doesNotMatch(renderedOutput, new RegExp(plaintextCanary));
  assert.doesNotMatch(renderedOutput, new RegExp(kekCanary));
  for (const token of tokens) {
    assert.notEqual(token, "");
    assert.doesNotMatch(renderedOutput, new RegExp(token));
  }
});

test("failed partial unlock retains cleanup ownership for plaintext rollback failures", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-partial-unlock-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const serverPolicy: ServerPolicy = {
    version: 1,
    sessionMinutes: 60,
    keyId: "partial-unlock-key",
    developmentUsers: [{ id: 101, login: "partial-unlock-user" }],
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
  const firstPlaintext = "FIRST=original\n";

  await initialize(root, authServer);
  await writeFile(path.join(root, "first.env"), firstPlaintext);
  await writeFile(path.join(root, "second.env"), "SECOND=original\n");
  await protect(root, "first.env");
  await protect(root, "second.env");
  const policy = await loadEnclist(root);
  serverPolicy.vaults[policy.vaultId] = {
    repository: "local/partial-unlock",
    files: {
      "first.env": { users: [101], teams: [] },
      "second.env": { users: [101], teams: [] },
    },
  };
  await login(root, authServer, 101);
  await seal(root, []);
  await rm(path.join(root, "first.env"));
  await rm(path.join(root, "second.env"));
  serverPolicy.vaults[policy.vaultId]!.files["second.env"] = { users: [], teams: [] };

  const originalFetch = globalThis.fetch;
  let unwraps = 0;
  globalThis.fetch = async (input, init) => {
    if (new URL(String(input)).pathname === "/v1/keys/unwrap" && ++unwraps === 2) {
      await writeFile(path.join(root, "first.env"), "FIRST=modified during rollback\n");
    }
    return originalFetch(input, init);
  };
  try {
    await assert.rejects(() => unlock(root, []), /modified materialized file first\.env/);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(await readFile(path.join(root, "first.env"), "utf8"), "FIRST=modified during rollback\n");
  await assert.rejects(() => stat(path.join(root, "second.env")), { code: "ENOENT" });
  const lease = await loadLease(root);
  assert.deepEqual(lease.paths.map((file) => file.path), ["first.env"]);
  assert.equal(lease.paths[0]!.digest, materializationDigest(Buffer.from(firstPlaintext)));
});

test("lock and failed unlock preserve plaintext without a lease", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-no-lease-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("lock rejects a lease path outside the repository without deleting it", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-lease-traversal-");
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

test("commands reject RoleGit state homes inside the worktree before writing state", async (context) => {
  for (const location of ["state", "."]) {
    const root = await temporaryDirectory(context, `rolegit-local-home-${location === "." ? "root" : "child"}-`);
    const home = location === "." ? root : path.join(root, location);
    process.env.ROLEGIT_HOME = home;
    execFileSync("git", ["init", "--quiet"], { cwd: root });
    const session = localSession("http://127.0.0.1:8787", 101, `local-home-${location}-token`);

    await assert.rejects(() => initialize(root, session.server), /ROLEGIT_HOME must be outside/);
    await assert.rejects(() => saveSession(root, session), /ROLEGIT_HOME must be outside/);
    await assert.rejects(() => stat(path.join(root, ".enclist")), { code: "ENOENT" });
    await assert.rejects(() => stat(path.join(root, ".git", "rolegit-id")), { code: "ENOENT" });
    for (const directory of ["sessions", "repositories", "leases"]) {
      await assert.rejects(() => stat(path.join(home, directory)), { code: "ENOENT" });
    }
    execFileSync("git", ["add", "."], { cwd: root });
    assert.equal(execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8" }), "");
  }
});

test("lock preserves changed files but cleans other paths and the session", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-dirty-lock-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("expiry cleanup does not extend a lease across sessions or delete changed files", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-identity-expiry-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const alice = localSession("http://127.0.0.1:8787", 101, "alice-token");
  const bob = localSession(alice.server, 202, "bob-token");
  const original = Buffer.from("original\n");
  const paths = ["dirty.env", "replaced.env", "clean.env"];
  for (const entry of paths) await writeFile(path.join(root, entry), original);
  const lease = leaseFor(root, alice, paths.map((entry) => ({
    path: entry,
    digest: materializationDigest(original),
  })));
  await saveLease(lease);
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
    () => lockIfSessionExpired(root, new Date(Date.now() - 1_000).toISOString(), lease.generation),
    /dirty\.env.*replaced\.env/,
  );
  assert.equal(await readFile(path.join(root, "dirty.env"), "utf8"), "unsaved edit\n");
  assert.ok((await stat(path.join(root, "replaced.env"))).isDirectory());
  await assert.rejects(() => stat(path.join(root, "clean.env")), { code: "ENOENT" });
  const retainedLease = await loadLease(root);
  assert.equal(retainedLease.sessionId, sessionId(alice));
  assert.deepEqual(retainedLease.paths.map((file) => file.path).sort(), ["dirty.env", "replaced.env"]);
  await writeFile(path.join(root, "clean.env"), original);
  await assert.rejects(
    () => lockIfSessionExpired(root, new Date(Date.now() - 1_000).toISOString(), lease.generation),
    /dirty\.env.*replaced\.env/,
  );
  assert.equal(await readFile(path.join(root, "clean.env"), "utf8"), original.toString("utf8"));
  assert.deepEqual((await loadLease(root)).paths.map((file) => file.path).sort(), ["dirty.env", "replaced.env"]);
  await assert.rejects(() => login(root, alice.server, 303), /files are unlocked/);
  assert.equal((await loadSession(root, bob.server)).user.id, bob.user.id);
});

test("partial automatic cleanup retires every successful path around failures", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-partial-expiry-progress-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const session = localSession("http://127.0.0.1:8787", 101, "partial-expiry-progress-token");
  const original = Buffer.from("partial cleanup materialization\n");
  const paths = ["first-clean.env", "dirty.env", "second-clean.env"];
  for (const entry of paths) await writeFile(path.join(root, entry), original);
  const lease = leaseFor(root, session, paths.map((entry) => ({
    path: entry,
    digest: materializationDigest(original),
  })));
  await saveLease(lease);
  await writeFile(path.join(root, "dirty.env"), "modified materialization\n");

  await assert.rejects(
    () => lockIfSessionExpired(root, new Date(Date.now() - 1_000).toISOString(), lease.generation),
    /dirty\.env/,
  );
  assert.deepEqual((await loadLease(root)).paths.map((file) => file.path), ["dirty.env"]);
  await Promise.all([
    writeFile(path.join(root, "first-clean.env"), original),
    writeFile(path.join(root, "second-clean.env"), original),
  ]);

  await assert.rejects(
    () => lockIfSessionExpired(root, new Date(Date.now() - 1_000).toISOString(), lease.generation),
    /dirty\.env/,
  );
  assert.equal(await readFile(path.join(root, "first-clean.env"), "utf8"), original.toString("utf8"));
  assert.equal(await readFile(path.join(root, "second-clean.env"), "utf8"), original.toString("utf8"));
  assert.deepEqual((await loadLease(root)).paths.map((file) => file.path), ["dirty.env"]);
});

test("stale watcher leaves a replacement session lease and materialization intact", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-stale-watcher-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const original = Buffer.from("same materialization\n");
  const oldSession = localSession("http://127.0.0.1:8787", 101, "old-watcher-token");
  const newSession = localSession(oldSession.server, 101, "new-watcher-token");
  await writeFile(path.join(root, ".env"), original);
  const oldLease = leaseFor(root, oldSession, [{
    path: ".env",
    digest: materializationDigest(original),
  }]);
  await saveLease(oldLease);
  const watcher = lockIfSessionExpired(root, new Date(Date.now() + 100).toISOString(), oldLease.generation);
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

test("a watcher starting after lock cannot recreate a cleanup error", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-late-watcher-");
  const root = path.join(parent, "repository");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const session = localSession(
    "http://127.0.0.1:8787",
    101,
    "late-watcher-token",
    new Date(Date.now() + 1_000).toISOString(),
  );
  const plaintext = Buffer.from("late watcher materialization\n");
  await initialize(root, session.server);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  const identity = repositoryId(root);
  await lock(root, false);
  const leaseStatePath = path.join(
    process.env.ROLEGIT_HOME,
    "leases",
    `${createHash("sha256").update(identity).digest("hex")}.json`,
  );
  assert.equal(JSON.parse(await readFile(leaseStatePath, "utf8")).status, "completed");

  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { lockIfSessionExpired } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await lockIfSessionExpired(
      process.env.CHILD_ID,
      process.env.CHILD_EXPIRY,
      process.env.CHILD_GENERATION,
    );
  `, {
    CHILD_ID: identity,
    CHILD_EXPIRY: session.expiresAt,
    CHILD_GENERATION: lease.generation,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await child.ready;
  assert.equal(await child.exit, 0, child.stderr());
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  await assert.rejects(() => loadExpiryCleanupError(identity, lease.generation), { code: "ENOENT" });
});

test("a failed repeated unlock preserves the watched lease generation", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-failed-repeated-unlock-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const server = "http://127.0.0.1:8787";
  await initialize(root, server);
  const expiresAt = new Date(Date.now() + 2_500).toISOString();
  const session = localSession(server, 101, "failed-repeated-unlock-token", expiresAt);
  const plaintext = Buffer.from("existing repeated unlock materialization\n");
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);

  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { lockIfSessionExpired } from ${JSON.stringify(moduleUrl)};
    const watcher = lockIfSessionExpired(
      process.env.CHILD_ROOT,
      process.env.CHILD_EXPIRY,
      process.env.CHILD_GENERATION,
    );
    await new Promise((resolve) => setTimeout(resolve, 250));
    process.stdout.write("ready\\n");
    await watcher;
  `, {
    CHILD_ROOT: root,
    CHILD_EXPIRY: expiresAt,
    CHILD_GENERATION: lease.generation,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await child.ready;

  await assert.rejects(() => unlock(root, ["missing.env"]), /not listed in \.enclist/);
  assert.equal((await loadLease(root)).generation, lease.generation);
  assert.equal(await child.exit, 0);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  await assert.rejects(() => loadExpiryCleanupError(repositoryId(root), lease.generation), { code: "ENOENT" });
});

test("expiry watcher follows a checkout renamed before cleanup", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-moved-watcher-");
  const root = path.join(parent, "before");
  const movedRoot = path.join(parent, "after");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const expiresAt = new Date(Date.now() + 150).toISOString();
  const session = localSession("http://127.0.0.1:8787", 101, "moved-watcher-token", expiresAt);
  const plaintext = Buffer.from("moved watcher materialization\n");
  await initialize(root, session.server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  const identity = repositoryId(root);
  const watcher = lockIfSessionExpired(identity, expiresAt, lease.generation);
  await delay(50);
  await rename(root, movedRoot);

  await watcher;
  await assert.rejects(() => stat(path.join(movedRoot, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(movedRoot), { code: "ENOENT" });
});

test("unresolved watcher moves retain the lease and a durable visible error", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-unresolved-watcher-");
  const root = path.join(parent, "before");
  const destinationParent = path.join(parent, "nested");
  const movedRoot = path.join(destinationParent, "after");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  await mkdir(destinationParent);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const expiresAt = new Date(Date.now() + 150).toISOString();
  const session = localSession("http://127.0.0.1:8787", 101, "unresolved-watcher-token", expiresAt);
  const plaintext = Buffer.from("unresolved watcher materialization\n");
  await initialize(root, session.server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  const identity = repositoryId(root);
  const watcher = lockIfSessionExpired(identity, expiresAt, lease.generation);
  await delay(50);
  await rename(root, movedRoot);

  await assert.rejects(() => watcher, /expiry cleanup remains pending/);
  assert.match((await loadExpiryCleanupError(identity)).message, /expiry cleanup remains pending/);
  assert.equal(await readFile(path.join(movedRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  const originalConsoleError = console.error;
  let warning = "";
  console.error = (...values: unknown[]) => {
    warning += values.join(" ");
  };
  try {
    await lock(movedRoot, false);
  } finally {
    console.error = originalConsoleError;
  }
  assert.match(warning, /previous expiry cleanup failed.*expiry cleanup remains pending/);
  await assert.rejects(() => loadExpiryCleanupError(identity), { code: "ENOENT" });
});

test("unlock cleans an unchanged lease after offline session expiry", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-offline-expiry-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("failed unlock expiry cleanup retains ownership and blocks replacement login", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-failed-unlock-expiry-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const session = localSession(
    "http://127.0.0.1:8787",
    101,
    "failed-unlock-expiry-token",
    new Date(Date.now() - 1_000).toISOString(),
  );
  const original = Buffer.from("original expired unlock materialization\n");
  await initialize(root, session.server);
  await writeFile(path.join(root, ".env"), "modified expired unlock materialization\n");
  await saveSession(root, session);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(original) }]));

  await assert.rejects(() => unlock(root, []), /modified materialized file/);
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
  await assert.rejects(() => login(root, session.server, 202), /expired lease cleanup.*modified materialized file/);
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
});

test("concurrent same-session lease updates retain every materialized path", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-concurrent-lease-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("concurrent lock and lease extension cannot orphan plaintext", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-concurrent-lock-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("a killed materialization process leaves durable cleanup ownership", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-crash-reservation-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const plaintext = Buffer.from("crash-owned materialization\n");
  const generation = randomUUID();
  const moduleUrl = new URL("../src/session.js", import.meta.url).href;
  const filesUrl = new URL("../src/files.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { materializationDigest, writeMaterializedFile } from ${JSON.stringify(filesUrl)};
    import { repositoryId, repositoryInstance, saveLease } from ${JSON.stringify(moduleUrl)};
    const plaintext = Buffer.from(process.env.CHILD_PLAINTEXT, "utf8");
    const file = { path: "crash.env", digest: materializationDigest(plaintext) };
    await saveLease({
      version: 1,
      repositoryId: repositoryId(process.env.CHILD_ROOT),
      repositoryInstance: repositoryInstance(process.env.CHILD_ROOT),
      generation: process.env.CHILD_GENERATION,
      root: process.env.CHILD_ROOT,
      server: "http://127.0.0.1:8787",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      userId: 101,
      sessionId: "a".repeat(64),
      paths: [file],
    });
    await writeMaterializedFile(process.env.CHILD_ROOT, file.path, plaintext);
    process.stdout.write("ready\\n");
    await new Promise(() => setInterval(() => undefined, 1_000));
  `, {
    CHILD_GENERATION: generation,
    CHILD_PLAINTEXT: plaintext.toString("utf8"),
    CHILD_ROOT: root,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await child.ready;
  child.child.kill("SIGKILL");
  assert.equal(await child.exit, null);
  assert.equal(child.child.signalCode, "SIGKILL");
  assert.equal((await loadLease(root)).generation, generation);
  assert.equal(await readFile(path.join(root, "crash.env"), "utf8"), plaintext.toString("utf8"));

  await lock(root, false);
  await assert.rejects(() => stat(path.join(root, "crash.env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
});

test("concurrent initializers serialize across processes", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-concurrent-init-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const script = `
    import { initialize } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await initialize(process.env.CHILD_ROOT, process.env.CHILD_SERVER);
  `;
  let release!: () => void;
  let entered!: () => void;
  const enteredLock = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const releaseLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  const holder = withRepositoryLock(root, async () => {
    entered();
    await releaseLock;
  });
  await enteredLock;
  const children = ["http://127.0.0.1:8787", "http://127.0.0.1:8788"].map((server) =>
    spawnTestProcess(context, script, {
      CHILD_ROOT: root,
      CHILD_SERVER: server,
      ROLEGIT_HOME: home,
    }));
  await Promise.all(children.map(({ ready }) => ready));
  await delay(100);
  assert.equal(children.every(({ child }) => child.exitCode === null), true);
  release();
  await holder;
  const exitCodes = await Promise.all(children.map(({ exit }) => exit));
  assert.deepEqual(exitCodes.sort(), [0, 1]);
  const policy = await loadEnclist(root);
  assert.deepEqual(await loadRepositoryServers(root), [policy.authServer]);
});

test("concurrent protect commands retain every policy update", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-concurrent-protect-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  await initialize(root, "http://127.0.0.1:8787");
  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const script = `
    import { protect } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await protect(process.env.CHILD_ROOT, process.env.CHILD_PATH);
  `;
  let release!: () => void;
  let entered!: () => void;
  const enteredLock = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const releaseLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  const holder = withRepositoryLock(root, async () => {
    entered();
    await releaseLock;
  });
  await enteredLock;
  const protectedPaths = ["first.env", "second.env", "third.env", "fourth.env"];
  const children = protectedPaths.map((protectedPath) => spawnTestProcess(context, script, {
    CHILD_ROOT: root,
    CHILD_PATH: protectedPath,
    ROLEGIT_HOME: home,
  }));
  await Promise.all(children.map(({ ready }) => ready));
  await delay(100);
  assert.equal(children.every(({ child }) => child.exitCode === null), true);
  release();
  await holder;
  for (const child of children) assert.equal(await child.exit, 0, child.stderr());
  assert.deepEqual(Object.keys((await loadEnclist(root)).files).sort(), protectedPaths.sort());
});

test("lock uses repository metadata after enclist removal", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-repository-session-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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
  const root = await temporaryDirectory(context, "rolegit-failed-logout-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("a killed lock owner fails closed for every concurrent waiter", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-killed-lock-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  const moduleUrl = new URL("../src/session.js", import.meta.url).href;
  const script = `
    import { withRepositoryLock } from ${JSON.stringify(moduleUrl)};
    await withRepositoryLock(process.env.CHILD_ROOT, async () => {
      process.stdout.write("locked");
      await new Promise(() => setInterval(() => undefined, 1_000));
    });
  `;
  const owner = spawnTestProcess(context, script, { CHILD_ROOT: root, ROLEGIT_HOME: home });
  await owner.ready;
  owner.child.kill("SIGKILL");
  await owner.exit;

  const session = localSession("http://127.0.0.1:8787", 101, "stale-lock-token");
  const results = await Promise.allSettled(
    Array.from({ length: 8 }, () => saveLease(leaseFor(root, session, []))),
  );
  assert.equal(results.every((result) =>
    result.status === "rejected" && /stale state lock/.test(String(result.reason))), true);
  await rm(instanceLockPath(root, home));
  await rm(operationLockPath(root, home));
  await saveLease(leaseFor(root, session, []));
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
});

test("a dead lock that vanishes or is replaced during liveness checking is retried", async (context) => {
  for (const outcome of ["vanished", "replaced"] as const) {
    const root = await temporaryDirectory(context, `rolegit-${outcome}-lock-`);
    const home = `${root}-home`;
    process.env.ROLEGIT_HOME = home;
    const destination = instanceLockPath(root, home);
    await mkdir(path.dirname(destination), { recursive: true });
    const initialPid = 1_000_001;
    const replacementPid = 1_000_002;
    await writeFile(destination, JSON.stringify({
      pid: initialPid,
      token: "initial-owner",
      createdAt: Date.now(),
    }));
    const checkedPids: number[] = [];
    const originalKill = process.kill;
    process.kill = ((pid: number, signal?: string | number) => {
      if (signal === 0 && (pid === initialPid || pid === replacementPid)) {
        checkedPids.push(pid);
        if (outcome === "replaced" && pid === initialPid) {
          writeFileSync(destination, JSON.stringify({
            pid: replacementPid,
            token: "replacement-owner",
            createdAt: Date.now(),
          }));
        } else {
          rmSync(destination);
        }
        throw Object.assign(new Error("process not found"), { code: "ESRCH" });
      }
      return originalKill(pid, signal);
    }) as typeof process.kill;
    try {
      await withRepositoryLock(root, async () => undefined);
    } finally {
      process.kill = originalKill;
    }
    assert.deepEqual(checkedPids, outcome === "replaced" ? [initialPid, replacementPid] : [initialPid]);
  }
});

test("a dead lock with the same token still fails closed after revalidation", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-retained-stale-lock-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  const destination = instanceLockPath(root, home);
  await mkdir(path.dirname(destination), { recursive: true });
  const stalePid = 1_000_003;
  await writeFile(destination, JSON.stringify({
    pid: stalePid,
    token: "retained-owner",
    createdAt: Date.now(),
  }));
  const originalKill = process.kill;
  process.kill = ((pid: number, signal?: string | number) => {
    if (signal === 0 && pid === stalePid) {
      throw Object.assign(new Error("process not found"), { code: "ESRCH" });
    }
    return originalKill(pid, signal);
  }) as typeof process.kill;
  try {
    await assert.rejects(() => withRepositoryLock(root, async () => undefined), /stale state lock/);
  } finally {
    process.kill = originalKill;
  }
  assert.equal(JSON.parse(await readFile(destination, "utf8")).token, "retained-owner");
});

test("invalid state locks fail closed without waiting for timeout", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-invalid-lock-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  const destination = operationLockPath(root, home);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, "{");
  await delay(125);
  const session = localSession("http://127.0.0.1:8787", 101, "invalid-lock-token");

  await assert.rejects(() => saveLease(leaseFor(root, session, [])), /invalid state lock/);
});

test("an old live lock is never reclaimed by age", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-live-lock-");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  const destination = operationLockPath(root, home);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, JSON.stringify({
    pid: process.pid,
    token: "live-owner",
    createdAt: Date.now() - 2 * 60 * 60 * 1_000,
  }));
  const session = localSession("http://127.0.0.1:8787", 101, "live-lock-token");
  let entered = false;
  const waiter = saveLease(leaseFor(root, session, [])).then(() => {
    entered = true;
  });
  await delay(50);
  assert.equal(entered, false);
  await rm(destination);
  await waiter;
});

test("concurrent logins keep one local session and revoke the losing token", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-concurrent-login-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("expired-session cleanup cannot delete a concurrent replacement", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-session-transition-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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
  const root = await temporaryDirectory(context, "rolegit-server-change-");
  process.env.ROLEGIT_HOME = `${root}-home`;
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

test("changing servers requires locking active sessions and leases first", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-active-server-change-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  let firstLogouts = 0;
  let secondLogins = 0;
  const sessionResponse = (token: string) => JSON.stringify({
    session: {
      token,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      user: { id: 101, login: "server-change-user" },
    },
  });
  const first = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    if (request.url === "/v1/auth/development") response.end(sessionResponse("first-active-token"));
    else {
      firstLogouts += 1;
      response.end("{}");
    }
  });
  const second = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    if (request.url === "/v1/auth/development") {
      secondLogins += 1;
      response.end(sessionResponse("second-active-token"));
    } else response.end("{}");
  });
  first.listen(0, "127.0.0.1");
  second.listen(0, "127.0.0.1");
  await Promise.all([once(first, "listening"), once(second, "listening")]);
  context.after(() => first.close());
  context.after(() => second.close());
  const firstUrl = `http://127.0.0.1:${(first.address() as AddressInfo).port}`;
  const secondUrl = `http://127.0.0.1:${(second.address() as AddressInfo).port}`;
  await initialize(root, firstUrl);
  const firstSession = await login(root, firstUrl, 101);

  await assert.rejects(() => login(root, secondUrl, 101), /another server session is active/);
  assert.equal(secondLogins, 0);
  const plaintext = Buffer.from("active server lease\n");
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, firstSession, [{ path: ".env", digest: materializationDigest(plaintext) }]));
  await assert.rejects(() => login(root, secondUrl, 101), /files are unlocked/);
  assert.equal(secondLogins, 0);

  await lock(root);
  assert.equal(firstLogouts, 1);
  await login(root, secondUrl, 101);
  assert.equal(secondLogins, 1);
});

test("same-server login cleans expired materialization before replacing the session", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-expired-relogin-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  let logins = 0;
  const server = createServer((request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    if (request.url === "/v1/auth/development") {
      logins += 1;
      response.end(JSON.stringify({
        session: {
          token: "replacement-token",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          user: { id: 202, login: "replacement-user" },
        },
      }));
    } else response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const expired = localSession(url, 101, "expired-materialization-token", new Date(Date.now() - 1_000).toISOString());
  const plaintext = Buffer.from("expired login materialization\n");
  await initialize(root, url);
  await saveSession(root, expired);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, expired, [{ path: ".env", digest: materializationDigest(plaintext) }]));

  const replacement = await login(root, url, 202);
  assert.equal(logins, 1);
  assert.equal(replacement.user.id, 202);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  assert.equal((await loadSession(root, url)).token, replacement.token);
});

test("same-server login aborts before authentication when expired cleanup fails", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-failed-expired-relogin-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  let logins = 0;
  const server = createServer((request, response) => {
    if (request.url === "/v1/auth/development") logins += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const expired = localSession(url, 101, "failed-cleanup-token", new Date(Date.now() - 1_000).toISOString());
  const original = Buffer.from("original expired materialization\n");
  await initialize(root, url);
  await saveSession(root, expired);
  await writeFile(path.join(root, ".env"), "modified expired materialization\n");
  await saveLease(leaseFor(root, expired, [{ path: ".env", digest: materializationDigest(original) }]));

  await assert.rejects(() => login(root, url, 202), /expired lease cleanup.*modified materialized file/);
  assert.equal(logins, 0);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "modified expired materialization\n");
  assert.equal((await loadLease(root)).sessionId, sessionId(expired));
  await assert.rejects(() => login(root, url, 202), /expired lease cleanup.*modified materialized file/);
  assert.equal(logins, 0);
});

test("repository-scoped lock leaves another repository session and lease intact", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-repository-sessions-");
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

test("lock invalidates every server session associated with its repository", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-associated-servers-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  let firstLogouts = 0;
  let secondLogouts = 0;
  const first = createServer((_request, response) => {
    firstLogouts += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  const second = createServer((_request, response) => {
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
  const firstSession = localSession(firstUrl, 101, "first-associated-token");
  const secondSession = localSession(secondUrl, 101, "second-associated-token");
  const plaintext = Buffer.from("associated server\n");
  await initialize(root, firstUrl);
  await saveRepositoryServer(root, secondUrl);
  await Promise.all([
    saveSession(root, firstSession),
    saveSession(root, secondSession),
    writeFile(path.join(root, ".env"), plaintext),
  ]);
  await saveLease(leaseFor(root, firstSession, [{ path: ".env", digest: materializationDigest(plaintext) }]));

  await lock(root);
  assert.equal(firstLogouts, 1);
  assert.equal(secondLogouts, 1);
  await assert.rejects(() => loadSession(root, firstUrl), /run `rolegit login` first/);
  await assert.rejects(() => loadSession(root, secondUrl), /run `rolegit login` first/);
});

test("moving a checkout preserves cleanup ownership", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-moved-checkout-");
  const root = path.join(parent, "before");
  const movedRoot = path.join(parent, "after");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  let logouts = 0;
  const server = createServer((_request, response) => {
    logouts += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const session = localSession(url, 101, "moved-checkout-token");
  const plaintext = Buffer.from("moved checkout\n");
  await initialize(root, url);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]));
  await rename(root, movedRoot);

  await lock(movedRoot);
  assert.equal(logouts, 1);
  await assert.rejects(() => stat(path.join(movedRoot, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadSession(movedRoot, url), /run `rolegit login` first/);
  await assert.rejects(() => loadLease(movedRoot), { code: "ENOENT" });
});

test("missing checkout marker recovers the registered active identity", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-missing-checkout-marker-");
  const root = path.join(parent, "repository");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  let logouts = 0;
  const server = createServer((_request, response) => {
    logouts += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const session = localSession(url, 101, "missing-marker-token");
  const plaintext = Buffer.from("missing marker materialization\n");
  await initialize(root, url);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]));
  const identity = repositoryId(root);
  await rm(path.join(root, ".git", "rolegit-id"));

  await lock(root);
  assert.equal(logouts, 1);
  assert.equal(repositoryId(root), identity);
  assert.equal((await readFile(path.join(root, ".git", "rolegit-id"), "utf8")).trim(), identity);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  await assert.rejects(() => loadSession(root, url), /run `rolegit login` first/);
});

test("alternate Git context cannot rotate an active checkout identity", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-alternate-git-context-");
  const root = path.join(parent, "repository");
  const alternateGit = path.join(parent, "alternate.git");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  execFileSync("git", ["init", "--bare", "--quiet", alternateGit]);
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "alternate-git-context-token");
  const plaintext = Buffer.from("alternate Git context materialization\n");
  await initialize(root, server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  const identity = repositoryId(root);

  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { lock } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await lock(process.env.CHILD_ROOT, false);
  `, {
    CHILD_ROOT: root,
    GIT_DIR: alternateGit,
    GIT_WORK_TREE: root,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await child.ready;
  assert.equal(await child.exit, 0, child.stderr());
  assert.equal(repositoryId(root), identity);
  assert.equal((await readFile(path.join(alternateGit, "rolegit-id"), "utf8")).trim(), identity);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
  assert.equal((await loadSession(root, server)).token, session.token);
  await deleteSession(root, server);
});

test("conflicting alternate Git identity cannot consume active state", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-conflicting-git-context-");
  const root = path.join(parent, "repository");
  const alternateGit = path.join(parent, "alternate.git");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  execFileSync("git", ["init", "--bare", "--quiet", alternateGit]);
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "conflicting-git-context-token");
  const plaintext = Buffer.from("conflicting Git context materialization\n");
  await initialize(root, server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  const identity = repositoryId(root);
  const conflictingIdentity = randomUUID();
  await writeFile(path.join(alternateGit, "rolegit-id"), `${conflictingIdentity}\n`);

  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { lock } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await lock(process.env.CHILD_ROOT, false);
  `, {
    CHILD_ROOT: root,
    GIT_DIR: alternateGit,
    GIT_WORK_TREE: root,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await child.ready;
  assert.equal(await child.exit, 1);
  assert.match(child.stderr(), /active Git checkout identity.*conflicts with registered identity/);
  assert.equal(repositoryId(root), identity);
  assert.equal((await readFile(path.join(alternateGit, "rolegit-id"), "utf8")).trim(), conflictingIdentity);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadLease(root)).generation, lease.generation);
  assert.equal((await loadSession(root, server)).token, session.token);
  await lock(root, false);
  await deleteSession(root, server);
});

test("a checkout path alias retains cleanup ownership", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-checkout-alias-");
  const root = path.join(parent, "repository");
  const alias = path.join(parent, "alias");
  const home = path.join(parent, ".test-home");
  process.env.ROLEGIT_HOME = home;
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "aliased-checkout-token");
  const plaintext = Buffer.from("aliased checkout\n");
  await initialize(root, server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]));
  await symlink(root, alias, process.platform === "win32" ? "junction" : "dir");

  assert.equal((await loadSession(alias, server)).token, session.token);
  await lock(alias, false);
  await assert.rejects(() => stat(path.join(root, ".env")), { code: "ENOENT" });
  await assert.rejects(() => loadLease(root), { code: "ENOENT" });
});

test("relative RoleGit homes cannot change state namespace by working directory", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-relative-home-");
  const root = path.join(parent, "repository");
  const subdirectory = path.join(root, "nested");
  const home = `${root}-home`;
  process.env.ROLEGIT_HOME = home;
  await mkdir(subdirectory, { recursive: true });
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "relative-home-token");
  const plaintext = Buffer.from("relative home materialization\n");
  await initialize(root, server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]));
  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const script = `
    import { lock } from ${JSON.stringify(moduleUrl)};
    process.chdir(process.env.CHILD_CWD);
    process.stdout.write("ready\\n");
    await lock(process.env.CHILD_ROOT, false);
  `;
  const children = [root, subdirectory].map((cwd) => spawnTestProcess(context, script, {
    CHILD_CWD: cwd,
    CHILD_ROOT: root,
    ROLEGIT_HOME: ".rolegit-state",
  }));
  await Promise.all(children.map(({ ready }) => ready));
  assert.deepEqual(await Promise.all(children.map(({ exit }) => exit)), [1, 1]);
  for (const child of children) assert.match(child.stderr(), /ROLEGIT_HOME must be an absolute path/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
  assert.equal((await loadSession(root, server)).token, session.token);
  await lock(root, false);
});

test("a copy made before materialization cannot consume the original lease", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-copy-before-unlock-");
  const root = path.join(parent, "original");
  const copyRoot = path.join(parent, "copy");
  const home = path.join(parent, ".test-home");
  process.env.ROLEGIT_HOME = home;
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "copy-before-token");
  const plaintext = Buffer.from("original materialization\n");
  await initialize(root, server);
  await cp(root, copyRoot, { recursive: true });
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]));

  await assert.rejects(() => lock(copyRoot), /duplicate RoleGit checkout identity/);
  await assert.rejects(() => loadLease(copyRoot), /bound to another root/);
  await assert.rejects(() => loadSession(copyRoot, server), /duplicate RoleGit checkout identity/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
  assert.equal((await loadSession(root, server)).token, session.token);
  await lock(root, false);
});

test("a copy containing materialized plaintext cannot delete shared state", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-copy-after-unlock-");
  const root = path.join(parent, "original");
  const copyRoot = path.join(parent, "copy");
  const home = path.join(parent, ".test-home");
  process.env.ROLEGIT_HOME = home;
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "copy-after-token");
  const plaintext = Buffer.from("copied materialization\n");
  await initialize(root, server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  await saveLease(leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]));
  await cp(root, copyRoot, { recursive: true });

  await assert.rejects(() => lock(copyRoot), /duplicate RoleGit checkout identity/);
  await assert.rejects(() => loadLease(copyRoot), /bound to another root/);
  await assert.rejects(() => loadSession(copyRoot, server), /duplicate RoleGit checkout identity/);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal(await readFile(path.join(copyRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadLease(root)).sessionId, sessionId(session));
  assert.equal((await loadSession(root, server)).token, session.token);
  await lock(root, false);
  assert.equal(await readFile(path.join(copyRoot, ".env"), "utf8"), plaintext.toString("utf8"));
});

test("a copied checkout cannot claim a moved original lease", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-copy-moved-original-");
  const root = path.join(parent, "original");
  const copyRoot = path.join(parent, "copy");
  const movedRoot = path.join(parent, "moved");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await mkdir(root);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const server = "http://127.0.0.1:8787";
  const session = localSession(server, 101, "copy-moved-original-token");
  const plaintext = Buffer.from("moved original materialization\n");
  await initialize(root, server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  await cp(root, copyRoot, { recursive: true });
  await rename(root, movedRoot);

  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { lock } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await lock(process.env.CHILD_ROOT, false);
  `, { CHILD_ROOT: copyRoot, ROLEGIT_HOME: process.env.ROLEGIT_HOME });
  await child.ready;
  assert.equal(await child.exit, 1);
  assert.match(child.stderr(), /duplicate RoleGit checkout identity.*filesystem instance/);
  assert.equal(await readFile(path.join(movedRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal(await readFile(path.join(copyRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadLease(movedRoot)).generation, lease.generation);

  await lock(movedRoot, false);
  await assert.rejects(() => stat(path.join(movedRoot, ".env")), { code: "ENOENT" });
  assert.equal(await readFile(path.join(copyRoot, ".env"), "utf8"), plaintext.toString("utf8"));
});

test("an expiry watcher cannot consume a copied checkout after the original moves", async (context) => {
  const parent = await temporaryDirectory(context, "rolegit-copy-moved-watcher-");
  const root = path.join(parent, "original");
  const copyRoot = path.join(parent, "copy");
  const secondCopyRoot = path.join(parent, "second-copy");
  const destinationParent = path.join(parent, "nested");
  const movedRoot = path.join(destinationParent, "moved");
  process.env.ROLEGIT_HOME = path.join(parent, ".test-home");
  await Promise.all([mkdir(root), mkdir(destinationParent)]);
  execFileSync("git", ["init", "--quiet"], { cwd: root });
  const expiresAt = new Date(Date.now() + 750).toISOString();
  const session = localSession("http://127.0.0.1:8787", 101, "copy-moved-watcher-token", expiresAt);
  const plaintext = Buffer.from("copied watcher materialization\n");
  await initialize(root, session.server);
  await saveSession(root, session);
  await writeFile(path.join(root, ".env"), plaintext);
  const lease = leaseFor(root, session, [{ path: ".env", digest: materializationDigest(plaintext) }]);
  await saveLease(lease);
  const identity = repositoryId(root);
  await cp(root, copyRoot, { recursive: true });
  await cp(root, secondCopyRoot, { recursive: true });
  await rename(root, movedRoot);
  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const child = spawnTestProcess(context, `
    import { lockIfSessionExpired } from ${JSON.stringify(moduleUrl)};
    process.stdout.write("ready\\n");
    await lockIfSessionExpired(
      process.env.CHILD_ID,
      process.env.CHILD_EXPIRY,
      process.env.CHILD_GENERATION,
    );
  `, {
    CHILD_ID: identity,
    CHILD_EXPIRY: expiresAt,
    CHILD_GENERATION: lease.generation,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await child.ready;

  assert.equal(await child.exit, 1);
  assert.match(child.stderr(), /ambiguous checkout identity.*expiry cleanup remains pending/);
  assert.equal(await readFile(path.join(movedRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal(await readFile(path.join(copyRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal(await readFile(path.join(secondCopyRoot, ".env"), "utf8"), plaintext.toString("utf8"));
  assert.equal((await loadLease(movedRoot)).generation, lease.generation);
  assert.equal((await loadExpiryCleanupError(identity, lease.generation)).generation, lease.generation);
});

test("a stale watcher cannot erase a newer generation cleanup error", async (context) => {
  const root = await temporaryDirectory(context, "rolegit-overlapping-watchers-");
  process.env.ROLEGIT_HOME = `${root}-home`;
  const server = "http://127.0.0.1:8787";
  const original = Buffer.from("original watcher materialization\n");
  const oldExpiry = new Date(Date.now() + 3_000).toISOString();
  const oldSession = localSession(server, 101, "overlapping-old-token", oldExpiry);
  await writeFile(path.join(root, ".env"), original);
  const oldLease = leaseFor(root, oldSession, [{ path: ".env", digest: materializationDigest(original) }]);
  await saveLease(oldLease);
  const moduleUrl = new URL("../src/commands.js", import.meta.url).href;
  const watcherScript = `
    import { lockIfSessionExpired } from ${JSON.stringify(moduleUrl)};
    const watcher = lockIfSessionExpired(
      process.env.CHILD_ROOT,
      process.env.CHILD_EXPIRY,
      process.env.CHILD_GENERATION,
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    process.stdout.write("ready\\n");
    await watcher;
  `;
  const oldWatcher = spawnTestProcess(context, watcherScript, {
    CHILD_ROOT: root,
    CHILD_EXPIRY: oldExpiry,
    CHILD_GENERATION: oldLease.generation,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await oldWatcher.ready;
  await lock(root, false);

  const newExpiry = new Date(Date.now() + 750).toISOString();
  const newSession = localSession(server, 101, "overlapping-new-token", newExpiry);
  await writeFile(path.join(root, ".env"), original);
  const newLease = leaseFor(root, newSession, [{ path: ".env", digest: materializationDigest(original) }]);
  await saveLease(newLease);
  await writeFile(path.join(root, ".env"), "modified newer materialization\n");
  const newWatcher = spawnTestProcess(context, watcherScript, {
    CHILD_ROOT: root,
    CHILD_EXPIRY: newExpiry,
    CHILD_GENERATION: newLease.generation,
    ROLEGIT_HOME: process.env.ROLEGIT_HOME,
  });
  await newWatcher.ready;

  assert.equal(await newWatcher.exit, 1);
  assert.match(newWatcher.stderr(), /modified materialized file/);
  assert.equal((await loadExpiryCleanupError(repositoryId(root), newLease.generation)).generation, newLease.generation);
  assert.equal(await oldWatcher.exit, 0);
  assert.equal((await loadExpiryCleanupError(repositoryId(root), newLease.generation)).generation, newLease.generation);
  assert.equal((await loadLease(root)).generation, newLease.generation);
  assert.equal(await readFile(path.join(root, ".env"), "utf8"), "modified newer materialization\n");
});
