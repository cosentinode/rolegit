import { readFile, stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";

import { AuthClient } from "./auth-client.js";
import { decryptFile, encryptFile, parseEncryptedFile } from "./crypto.js";
import { decodeBase64Url } from "./encoding.js";
import {
  appendGitIgnore,
  assertSingleLinkPath,
  assertNoSymlinkPath,
  atomicWrite,
  gitPathIsIgnored,
  gitPathExistsInHistory,
  gitPathIsTracked,
  gitMetadataPaths,
  existingPortablePathAlias,
  materializationDigest,
  removeMaterializedFile,
  writeMaterializedFile,
} from "./files.js";
import {
  createEnclist,
  encryptedObjectPath,
  loadEnclist,
  normalizePlaintextPath,
  saveEnclist,
} from "./policy.js";
import { portablePathKey } from "./paths.js";
import {
  clearExpiryCleanupError,
  deleteLeaseUnlocked,
  deleteSessionUnlocked,
  loadLease,
  loadRepositoryServers,
  loadSessionUnlocked,
  repositoryId,
  repositoryInstance,
  refreshLeaseMaterializationUnlocked,
  recordExpiryCleanupError,
  replaceLeaseMaterializationsUnlocked,
  resolveRepositoryRoot,
  roleGitMetadataPath,
  saveLeaseUnlocked,
  saveRepositoryServerUnlocked,
  saveSessionUnlocked,
  sessionId,
  sessionTimeRemaining,
  withRepositoryLock,
} from "./session.js";
import type { LocalSession, MaterializationLease, MaterializedFile } from "./types.js";

const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_ENCRYPTED_FILE_SIZE = 4 * Math.ceil(MAX_FILE_SIZE / 3) + 64 * 1024;
const MAX_TIMER_DELAY = 2_147_483_647;

async function initializeUnlocked(root: string, authServer: string): Promise<void> {
  try {
    await stat(path.join(root, ".enclist"));
    throw new Error("repository already has a .enclist");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await saveEnclist(root, createEnclist(authServer));
  await saveRepositoryServerUnlocked(root, authServer);
  console.log("Created .enclist");
}

export function initialize(root: string, authServer: string): Promise<void> {
  return withRepositoryLock(root, () => initializeUnlocked(root, authServer));
}

async function protectUnlocked(root: string, inputPath: string): Promise<void> {
  const relativeInput = path.isAbsolute(inputPath) ? path.relative(root, inputPath) : inputPath;
  const protectedPath = normalizePlaintextPath(relativeInput);
  const portablePath = portablePathKey(protectedPath);
  const metadataNamespaces = [...gitMetadataPaths(root), roleGitMetadataPath(root)]
    .filter((entry): entry is string => entry !== undefined)
    .map(portablePathKey);
  if (metadataNamespaces.some((entry) =>
    entry === "." || portablePath === entry || portablePath.startsWith(`${entry}/`))) {
    throw new Error("RoleGit metadata cannot be protected");
  }
  const policy = await loadEnclist(root);
  const caseAlias = Object.keys(policy.files).find((entry) =>
    entry !== protectedPath && portablePathKey(entry) === portablePathKey(protectedPath));
  if (caseAlias) throw new Error(`${protectedPath} differs only by case from protected path ${caseAlias}`);
  if (gitPathIsTracked(root, protectedPath)) {
    throw new Error(`${protectedPath} is already tracked; remove it from Git history before protecting it`);
  }
  if (gitPathExistsInHistory(root, protectedPath)) {
    throw new Error(`${protectedPath} exists in Git history; rewrite the history and rotate its secrets first`);
  }
  const filesystemAlias = await existingPortablePathAlias(root, protectedPath);
  if (filesystemAlias) throw new Error(`${protectedPath} differs only by case from existing path ${filesystemAlias}`);
  await assertNoSymlinkPath(root, protectedPath);
  await assertSingleLinkPath(root, protectedPath);
  await appendGitIgnore(root, protectedPath);
  if (!gitPathIsIgnored(root, protectedPath)) {
    throw new Error(`failed to ignore plaintext path ${protectedPath}`);
  }
  policy.files[protectedPath] = { object: encryptedObjectPath(protectedPath) };
  await saveEnclist(root, policy);
  console.log(`Protected ${protectedPath}`);
  console.log(`Register vault ${policy.vaultId} and this path in the authorization service policy.`);
}

export function protect(root: string, inputPath: string): Promise<void> {
  return withRepositoryLock(root, () => protectUnlocked(root, inputPath));
}

function selectFiles(files: Record<string, { object: string }>, requested: string[]): string[] {
  if (requested.length === 0) return Object.keys(files);
  const normalized = requested.map(normalizePlaintextPath);
  for (const protectedPath of normalized) {
    if (!files[protectedPath]) throw new Error(`${protectedPath} is not listed in .enclist`);
  }
  return normalized;
}

async function cleanupMaterializedFiles(
  root: string,
  files: MaterializedFile[],
  log: boolean,
  retained?: MaterializedFile[],
): Promise<Error[]> {
  const failures: Error[] = [];
  for (const file of files) {
    try {
      await removeMaterializedFile(root, file);
      if (log) console.log(`Locked ${file.path}`);
    } catch (error) {
      retained?.push(file);
      failures.push(new Error(`${file.path}: ${(error as Error).message}`, { cause: error }));
    }
  }
  return failures;
}

async function cleanupLease(
  root: string,
  lease: MaterializationLease,
  log: boolean,
  retainOnFailure = false,
): Promise<Error[]> {
  let current: MaterializationLease;
  try {
    current = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    return [error as Error];
  }
  if (current.generation !== lease.generation) return [];

  const failures = await cleanupMaterializedFiles(root, current.paths, log);
  if (!retainOnFailure || failures.length === 0) {
    await deleteLeaseUnlocked(root).catch((error: unknown) => failures.push(error as Error));
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

async function cleanupExpiredLease(root: string, retainOnFailure = false): Promise<Error[]> {
  let lease: MaterializationLease;
  try {
    lease = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  if (new Date(lease.expiresAt).getTime() > Date.now()) return [];
  return cleanupLease(root, lease, false, retainOnFailure);
}

async function sealUnlocked(root: string, requested: string[]): Promise<void> {
  const policy = await loadEnclist(root);
  const session = await loadSessionUnlocked(root, policy.authServer);
  const client = new AuthClient(policy.authServer);
  for (const protectedPath of selectFiles(policy.files, requested)) {
    if (!gitPathIsIgnored(root, protectedPath) || gitPathIsTracked(root, protectedPath)) {
      throw new Error(`refusing to seal ${protectedPath}: plaintext must be ignored and untracked`);
    }
    await assertNoSymlinkPath(root, protectedPath);
    const source = path.join(root, protectedPath);
    const sourceStat = await stat(source);
    if (!sourceStat.isFile()) throw new Error(`${protectedPath} is not a regular file`);
    if (sourceStat.nlink > 1) throw new Error(`refusing multiply-linked plaintext path: ${protectedPath}`);
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
      await refreshLeaseMaterializationUnlocked(root, session, {
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

export function seal(root: string, requested: string[]): Promise<void> {
  return withRepositoryLock(root, () => sealUnlocked(root, requested));
}

async function unlockUnlocked(
  root: string,
  requested: string[],
): Promise<{ session: LocalSession; leaseGeneration: string }> {
  const policy = await loadEnclist(root);
  const staleFailures = await cleanupExpiredLease(root, true);
  let session: LocalSession;
  try {
    session = await loadSessionUnlocked(root, policy.authServer);
  } catch (error) {
    throwWithCleanupFailures(error, staleFailures);
  }
  if (staleFailures.length > 0) {
    throw cleanupError("expired lease cleanup completed with errors", staleFailures);
  }
  const client = new AuthClient(policy.authServer);
  let previousLease: MaterializationLease | undefined;
  try {
    previousLease = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const lease: MaterializationLease = {
    version: 1,
    repositoryId: repositoryId(root),
    repositoryInstance: repositoryInstance(root),
    generation: previousLease?.generation ?? randomUUID(),
    root: path.resolve(root),
    server: policy.authServer,
    expiresAt: session.expiresAt,
    userId: session.user.id,
    sessionId: sessionId(session),
    paths: [],
  };
  await saveLeaseUnlocked(lease);
  const owned: MaterializedFile[] = [];
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
          await saveLeaseUnlocked({ ...lease, paths: [file] });
          try {
            await writeMaterializedFile(root, protectedPath, plaintext);
            owned.push(file);
          } catch (error) {
            const cause = (error as Error).cause as NodeJS.ErrnoException | undefined;
            if (cause?.code !== "EEXIST") owned.push(file);
            throw error;
          }
        } finally {
          plaintext.fill(0);
        }
        console.log(`Unlocked ${protectedPath}`);
      } finally {
        key.fill(0);
      }
    }
  } catch (error) {
    const retained: MaterializedFile[] = [];
    const failures = await cleanupMaterializedFiles(root, owned, false, retained);
    try {
      await replaceLeaseMaterializationsUnlocked({ ...lease, paths: [...(previousLease?.paths ?? []), ...retained] });
    } catch (leaseError) {
      failures.push(leaseError as Error);
    }
    throwWithCleanupFailures(error, failures);
  }
  return { session, leaseGeneration: lease.generation };
}

export function unlock(
  root: string,
  requested: string[],
): Promise<{ session: LocalSession; leaseGeneration: string }> {
  return withRepositoryLock(root, () => unlockUnlocked(root, requested));
}

async function lockUnlocked(root: string, logout: boolean): Promise<void> {
  const failures: Error[] = [];
  let lease: MaterializationLease | undefined;
  try {
    lease = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(error as Error);
  }
  if (lease) failures.push(...await cleanupLease(root, lease, true));

  if (logout) {
    const servers = new Set<string>();
    if (lease) servers.add(lease.server);
    try {
      for (const server of await loadRepositoryServers(root)) servers.add(server);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(error as Error);
    }
    if (servers.size === 0) {
      try {
        const server = (await loadEnclist(root)).authServer;
        await saveRepositoryServerUnlocked(root, server);
        servers.add(server);
      } catch (error) {
        failures.push(new Error(
          `cannot determine authorization server: ${(error as Error).message}`,
          { cause: error },
        ));
      }
    }
    for (const server of servers) {
      let session: LocalSession | undefined;
      try {
        session = await loadSessionUnlocked(root, server);
      } catch {
        // Invalid, expired, or missing local sessions still need deletion.
      }
      if (session) {
        try {
          await new AuthClient(server).logout(session);
        } catch (error) {
          failures.push(new Error(`remote logout failed: ${(error as Error).message}`, { cause: error }));
        }
      }
      try {
        await deleteSessionUnlocked(root, server, session && sessionId(session));
      } catch (error) {
        failures.push(error as Error);
      }
    }
  }
  if (failures.length > 0) throw cleanupError("lock completed with errors", failures);
}

export function lock(root: string, logout = true): Promise<void> {
  return withRepositoryLock(root, async () => {
    await lockUnlocked(root, logout);
    await clearExpiryCleanupError(repositoryId(root));
  });
}

export function expiryWatcherDelay(expiresAt: string, now = Date.now()): number {
  const expiration = new Date(expiresAt).getTime();
  if (!Number.isFinite(expiration)) throw new Error("invalid expiry watcher expiration");
  return Math.min(MAX_TIMER_DELAY, Math.max(0, expiration - now + 250));
}

async function withResolvedRepositoryLock<T>(
  repositoryIdentity: string,
  operation: (root: string) => Promise<T>,
): Promise<T> {
  const root = await resolveRepositoryRoot(repositoryIdentity);
  try {
    return await withRepositoryLock(root, () => operation(root));
  } catch (error) {
    const retryRoot = await resolveRepositoryRoot(repositoryIdentity);
    if (path.resolve(retryRoot) === path.resolve(root)) throw error;
    return withRepositoryLock(retryRoot, () => operation(retryRoot));
  }
}

export async function lockIfSessionExpired(
  rootOrIdentity: string,
  expectedExpiry: string,
  expectedGeneration: string,
): Promise<void> {
  if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(expectedGeneration)) {
    throw new Error("invalid expiry watcher generation");
  }
  const originalRoot = path.isAbsolute(rootOrIdentity) ? rootOrIdentity : undefined;
  const repositoryIdentity = originalRoot ? repositoryId(originalRoot) : rootOrIdentity;
  const withWatcherLock = originalRoot && /^[a-f0-9]{64}$/.test(repositoryIdentity)
    ? <T>(operation: (root: string) => Promise<T>) => withRepositoryLock(originalRoot, () => operation(originalRoot))
    : <T>(operation: (root: string) => Promise<T>) => withResolvedRepositoryLock(repositoryIdentity, operation);
  try {
    const watchedLease = await withWatcherLock(loadLease);
    if (watchedLease.generation !== expectedGeneration) return;
    let expiry = expectedExpiry;
    while (true) {
      const delay = expiryWatcherDelay(expiry);
      await new Promise((resolve) => setTimeout(resolve, delay));
      const nextExpiry = await withWatcherLock(async (root) => {
        let lease: MaterializationLease;
        try {
          lease = await loadLease(root);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
          throw error;
        }
        if (lease.generation !== watchedLease.generation) return undefined;
        let current: LocalSession;
        try {
          current = await loadSessionUnlocked(root, lease.server);
        } catch {
          const failures = await cleanupLease(root, lease, false, true);
          if (failures.length > 0) throw cleanupError("expiry cleanup completed with errors", failures);
          return undefined;
        }
        if (current.user.id !== lease.userId || sessionId(current) !== lease.sessionId) {
          const failures = await cleanupLease(root, lease, false, true);
          if (failures.length > 0) throw cleanupError("expiry cleanup completed with errors", failures);
          return undefined;
        }
        return current.expiresAt;
      });
      if (!nextExpiry) break;
      expiry = nextExpiry;
    }
    await clearExpiryCleanupError(repositoryIdentity, expectedGeneration);
  } catch (error) {
    try {
      const recorded = await recordExpiryCleanupError(repositoryIdentity, expectedGeneration, error);
      if (!recorded) return;
    } catch (recordError) {
      throw new AggregateError([error, recordError], "expiry cleanup failed and its error could not be persisted");
    }
    throw error;
  }
}

async function loginUnlocked(
  root: string,
  server: string,
  developmentUser?: number,
): Promise<LocalSession> {
  const expiredLeaseFailures = await cleanupExpiredLease(root, true);
  if (expiredLeaseFailures.length > 0) {
    throw cleanupError("expired lease cleanup completed with errors", expiredLeaseFailures);
  }
  try {
    await loadLease(root);
    throw new Error("files are unlocked; run `rolegit lock` before logging in again");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  try {
    for (const previousServer of await loadRepositoryServers(root)) {
      if (previousServer === server) continue;
      try {
        await loadSessionUnlocked(root, previousServer);
        throw new Error(`another server session is active (${previousServer}); run \`rolegit lock\` first`);
      } catch (error) {
        if (!/no RoleGit session|RoleGit session expired/.test((error as Error).message)) throw error;
      }
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
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
  let saved = false;
  try {
    await saveSessionUnlocked(root, session);
    saved = true;
    await saveRepositoryServerUnlocked(root, server);
  } catch (error) {
    if (saved) await deleteSessionUnlocked(root, server, sessionId(session)).catch(() => undefined);
    try {
      await client.logout(session);
    } catch (logoutError) {
      throw new AggregateError(
        [error, logoutError],
        `failed to persist session and revoke replacement token: ${(logoutError as Error).message}`,
      );
    }
    throw error;
  }
  console.log(`Logged in as ${session.user.login}`);
  console.log(`Session expires at ${session.expiresAt}`);
  return session;
}

export function login(
  root: string,
  server: string,
  developmentUser?: number,
): Promise<LocalSession> {
  return withRepositoryLock(root, () => loginUnlocked(root, server, developmentUser));
}

async function printStatusUnlocked(root: string, server: string): Promise<void> {
  const session = await loadSessionUnlocked(root, server);
  const minutes = Math.ceil(sessionTimeRemaining(session) / 60_000);
  console.log(`${session.user.login}: ${minutes} minute${minutes === 1 ? "" : "s"} remaining`);
}

export function printStatus(root: string, server: string): Promise<void> {
  return withRepositoryLock(root, () => printStatusUnlocked(root, server));
}
