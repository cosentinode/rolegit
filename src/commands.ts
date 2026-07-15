import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { AuthClient } from "./auth-client.js";
import { decryptFile, encryptFile, parseEncryptedFile } from "./crypto.js";
import { decodeBase64Url } from "./encoding.js";
import {
  appendGitIgnore,
  assertNoSymlinkPath,
  atomicWrite,
  gitPathIsIgnored,
  gitPathExistsInHistory,
  gitPathIsTracked,
  materializationDigest,
  removeMaterializedFile,
  writeMaterializedFile,
} from "./files.js";
import {
  createEnclist,
  encryptedObjectPath,
  loadEnclist,
  normalizeProtectedPath,
  saveEnclist,
} from "./policy.js";
import {
  deleteLease,
  deleteSession,
  loadLease,
  loadSession,
  refreshLeaseMaterialization,
  saveLease,
  saveSession,
  sessionId,
  sessionTimeRemaining,
} from "./session.js";
import type { LocalSession, MaterializationLease, MaterializedFile } from "./types.js";

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_ENCRYPTED_FILE_SIZE = 4 * Math.ceil(MAX_FILE_SIZE / 3) + 64 * 1024;

export async function initialize(root: string, authServer: string): Promise<void> {
  try {
    await stat(path.join(root, ".enclist"));
    throw new Error("repository already has a .enclist");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await saveEnclist(root, createEnclist(authServer));
  console.log("Created .enclist");
}

export async function protect(root: string, inputPath: string): Promise<void> {
  const relativeInput = path.isAbsolute(inputPath) ? path.relative(root, inputPath) : inputPath;
  const protectedPath = normalizeProtectedPath(relativeInput);
  if (protectedPath === ".enclist" || protectedPath.startsWith(".rolegit/")) {
    throw new Error("RoleGit metadata cannot be protected");
  }
  if (gitPathIsTracked(root, protectedPath)) {
    throw new Error(`${protectedPath} is already tracked; remove it from Git history before protecting it`);
  }
  if (gitPathExistsInHistory(root, protectedPath)) {
    throw new Error(`${protectedPath} exists in Git history; rewrite the history and rotate its secrets first`);
  }
  await assertNoSymlinkPath(root, protectedPath);
  await appendGitIgnore(root, protectedPath);
  if (!gitPathIsIgnored(root, protectedPath)) {
    throw new Error(`failed to ignore plaintext path ${protectedPath}`);
  }
  const policy = await loadEnclist(root);
  policy.files[protectedPath] = { object: encryptedObjectPath(protectedPath) };
  await saveEnclist(root, policy);
  console.log(`Protected ${protectedPath}`);
  console.log(`Register vault ${policy.vaultId} and this path in the authorization service policy.`);
}

function selectFiles(files: Record<string, { object: string }>, requested: string[]): string[] {
  if (requested.length === 0) return Object.keys(files);
  const normalized = requested.map(normalizeProtectedPath);
  for (const protectedPath of normalized) {
    if (!files[protectedPath]) throw new Error(`${protectedPath} is not listed in .enclist`);
  }
  return normalized;
}

async function cleanupMaterializedFiles(
  root: string,
  files: MaterializedFile[],
  log: boolean,
): Promise<Error[]> {
  const failures: Error[] = [];
  for (const file of files) {
    try {
      await removeMaterializedFile(root, file);
      if (log) console.log(`Locked ${file.path}`);
    } catch (error) {
      failures.push(new Error(`${file.path}: ${(error as Error).message}`, { cause: error }));
    }
  }
  return failures;
}

async function cleanupLease(root: string, lease: MaterializationLease, log: boolean): Promise<Error[]> {
  let current: MaterializationLease;
  try {
    current = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    return [error as Error];
  }
  if (current.sessionId !== lease.sessionId) return [];

  const failures = await cleanupMaterializedFiles(root, current.paths, log);
  try {
    const latest = await loadLease(root);
    if (latest.sessionId === lease.sessionId) await deleteLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(error as Error);
  }
  return failures;
}

function throwWithCleanupFailures(error: unknown, failures: Error[]): never {
  if (failures.length > 0) {
    throw new AggregateError(
      [error, ...failures],
      `operation failed and some materialized files changed: ${failures.map((failure) => failure.message).join("; ")}`,
    );
  }
  throw error;
}

function cleanupError(message: string, failures: Error[]): AggregateError {
  return new AggregateError(
    failures,
    `${message}: ${failures.map((failure) => failure.message).join("; ")}`,
  );
}

async function cleanupExpiredLease(root: string): Promise<Error[]> {
  let lease: MaterializationLease;
  try {
    lease = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  if (new Date(lease.expiresAt).getTime() > Date.now()) return [];
  return cleanupLease(root, lease, false);
}

export async function seal(root: string, requested: string[]): Promise<void> {
  const policy = await loadEnclist(root);
  const session = await loadSession(policy.authServer);
  const client = new AuthClient(policy.authServer);
  for (const protectedPath of selectFiles(policy.files, requested)) {
    if (!gitPathIsIgnored(root, protectedPath) || gitPathIsTracked(root, protectedPath)) {
      throw new Error(`refusing to seal ${protectedPath}: plaintext must be ignored and untracked`);
    }
    await assertNoSymlinkPath(root, protectedPath);
    const source = path.join(root, protectedPath);
    const sourceStat = await stat(source);
    if (!sourceStat.isFile()) throw new Error(`${protectedPath} is not a regular file`);
    if (sourceStat.size > MAX_FILE_SIZE) throw new Error(`${protectedPath} exceeds the 10 MiB limit`);
    const plaintext = await readFile(source);
    const keyResult = await client.dataKey(session, policy.vaultId, protectedPath);
    if (!keyResult.wrappedKey) throw new Error("authorization service omitted the wrapped key");
    const key = decodeBase64Url(keyResult.key, 32);
    try {
      const encrypted = encryptFile(
        plaintext,
        key,
        keyResult.wrappedKey,
        policy.vaultId,
        protectedPath,
      );
      const objectPath = policy.files[protectedPath]!.object;
      await assertNoSymlinkPath(root, objectPath);
      await atomicWrite(
        path.join(root, objectPath),
        Buffer.from(`${JSON.stringify(encrypted, null, 2)}\n`),
        0o600,
      );
      await refreshLeaseMaterialization(root, session, {
        path: protectedPath,
        digest: materializationDigest(plaintext),
      });
      console.log(`Sealed ${protectedPath} -> ${objectPath}`);
    } finally {
      key.fill(0);
      plaintext.fill(0);
    }
  }
}

export async function unlock(root: string, requested: string[]): Promise<LocalSession> {
  const policy = await loadEnclist(root);
  const staleFailures = await cleanupExpiredLease(root);
  let session: LocalSession;
  try {
    session = await loadSession(policy.authServer);
  } catch (error) {
    throwWithCleanupFailures(error, staleFailures);
  }
  if (staleFailures.length > 0) {
    throw cleanupError("expired lease cleanup completed with errors", staleFailures);
  }
  const client = new AuthClient(policy.authServer);
  const materialized: MaterializedFile[] = [];
  try {
    for (const protectedPath of selectFiles(policy.files, requested)) {
      if (!gitPathIsIgnored(root, protectedPath) || gitPathIsTracked(root, protectedPath)) {
        throw new Error(`refusing to materialize ${protectedPath}: path must be ignored and untracked`);
      }
      await assertNoSymlinkPath(root, protectedPath);
      const objectPath = policy.files[protectedPath]!.object;
      await assertNoSymlinkPath(root, objectPath);
      const objectFile = path.join(root, objectPath);
      if ((await stat(objectFile)).size > MAX_ENCRYPTED_FILE_SIZE) {
        throw new Error(`encrypted object for ${protectedPath} exceeds the size limit`);
      }
      const encrypted = parseEncryptedFile(JSON.parse(await readFile(objectFile, "utf8")));
      if (decodeBase64Url(encrypted.ciphertext).length > MAX_FILE_SIZE) {
        throw new Error(`encrypted object for ${protectedPath} exceeds the size limit`);
      }
      const keyResult = await client.unwrap(
        session,
        policy.vaultId,
        protectedPath,
        encrypted.wrappedKey,
      );
      const key = decodeBase64Url(keyResult.key, 32);
      try {
        const plaintext = decryptFile(encrypted, key, policy.vaultId, protectedPath);
        try {
          const file = { path: protectedPath, digest: materializationDigest(plaintext) };
          await writeMaterializedFile(root, protectedPath, plaintext);
          materialized.push(file);
        } finally {
          plaintext.fill(0);
        }
        console.log(`Unlocked ${protectedPath}`);
      } finally {
        key.fill(0);
      }
    }
  } catch (error) {
    throwWithCleanupFailures(error, await cleanupMaterializedFiles(root, materialized, false));
  }
  try {
    await saveLease({
      version: 1,
      root: path.resolve(root),
      server: policy.authServer,
      expiresAt: session.expiresAt,
      userId: session.user.id,
      sessionId: sessionId(session),
      paths: materialized,
    });
  } catch (error) {
    throwWithCleanupFailures(error, await cleanupMaterializedFiles(root, materialized, false));
  }
  return session;
}

export async function lock(root: string, logout = true): Promise<void> {
  const failures: Error[] = [];
  let lease: MaterializationLease | undefined;
  try {
    lease = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(error as Error);
  }
  if (lease) failures.push(...await cleanupLease(root, lease, true));

  if (logout) {
    let server = lease?.server;
    if (!server) {
      try {
        server = (await loadEnclist(root)).authServer;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(error as Error);
      }
    }
    if (server) {
      try {
        const session = await loadSession(server);
        await new AuthClient(server).logout(session).catch(() => undefined);
      } catch {
        // Invalid, expired, or missing local sessions still need deletion.
      }
      try {
        await deleteSession(server);
      } catch (error) {
        failures.push(error as Error);
      }
    }
  }
  if (failures.length > 0) throw cleanupError("lock completed with errors", failures);
}

export async function lockIfSessionExpired(root: string, expectedExpiry: string): Promise<void> {
  const watchedLease = await loadLease(root);
  let expiry = expectedExpiry;
  while (true) {
    const delay = Math.max(0, new Date(expiry).getTime() - Date.now() + 250);
    await new Promise((resolve) => setTimeout(resolve, delay));
    let lease: MaterializationLease;
    try {
      lease = await loadLease(root);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (lease.sessionId !== watchedLease.sessionId) return;
    let current: LocalSession;
    try {
      current = await loadSession(lease.server);
    } catch {
      const failures = await cleanupLease(root, lease, false);
      if (failures.length > 0) throw cleanupError("expiry cleanup completed with errors", failures);
      return;
    }
    if (current.user.id !== lease.userId || sessionId(current) !== lease.sessionId) {
      const failures = await cleanupLease(root, lease, false);
      if (failures.length > 0) throw cleanupError("expiry cleanup completed with errors", failures);
      return;
    }
    expiry = current.expiresAt;
  }
}

export async function login(
  server: string,
  developmentUser?: number,
): Promise<LocalSession> {
  const client = new AuthClient(server);
  let session: LocalSession;
  if (developmentUser !== undefined) {
    session = await client.developmentLogin(developmentUser);
  } else {
    const device = await client.startDeviceLogin();
    console.log(`Open ${device.verificationUri}`);
    console.log(`Enter code: ${device.userCode}`);
    let interval = device.interval;
    while (true) {
      await new Promise((resolve) => setTimeout(resolve, interval * 1000));
      const result = await client.pollDeviceLogin(device.requestId);
      if (result.status === "complete") {
        session = { server, ...result.session };
        break;
      }
      interval = result.interval;
      if (new Date(device.expiresAt).getTime() <= Date.now()) {
        throw new Error("GitHub device login expired");
      }
    }
  }
  await saveSession(session);
  console.log(`Logged in as ${session.user.login}`);
  console.log(`Session expires at ${session.expiresAt}`);
  return session;
}

export async function printStatus(server: string): Promise<void> {
  const session = await loadSession(server);
  const minutes = Math.ceil(sessionTimeRemaining(session) / 60_000);
  console.log(`${session.user.login}: ${minutes} minute${minutes === 1 ? "" : "s"} remaining`);
}
