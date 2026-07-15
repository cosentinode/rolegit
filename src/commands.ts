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
  removeMaterializedFile,
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
  saveLease,
  saveSession,
  sessionTimeRemaining,
} from "./session.js";
import type { LocalSession } from "./types.js";

const MAX_FILE_SIZE = 10 * 1024 * 1024;

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
      await atomicWrite(
        path.join(root, objectPath),
        Buffer.from(`${JSON.stringify(encrypted, null, 2)}\n`),
        0o600,
      );
      console.log(`Sealed ${protectedPath} -> ${objectPath}`);
    } finally {
      key.fill(0);
      plaintext.fill(0);
    }
  }
}

export async function unlock(root: string, requested: string[]): Promise<LocalSession> {
  const policy = await loadEnclist(root);
  let session: LocalSession;
  try {
    session = await loadSession(policy.authServer);
  } catch (error) {
    for (const protectedPath of Object.keys(policy.files)) {
      await removeMaterializedFile(root, protectedPath);
    }
    throw error;
  }
  const client = new AuthClient(policy.authServer);
  const materialized: string[] = [];
  try {
    for (const protectedPath of selectFiles(policy.files, requested)) {
      if (!gitPathIsIgnored(root, protectedPath) || gitPathIsTracked(root, protectedPath)) {
        throw new Error(`refusing to materialize ${protectedPath}: path must be ignored and untracked`);
      }
      await assertNoSymlinkPath(root, protectedPath);
      const objectPath = policy.files[protectedPath]!.object;
      await assertNoSymlinkPath(root, objectPath);
      const objectFile = path.join(root, objectPath);
      if ((await stat(objectFile)).size > MAX_FILE_SIZE + 64 * 1024) {
        throw new Error(`encrypted object for ${protectedPath} exceeds the size limit`);
      }
      const encrypted = parseEncryptedFile(JSON.parse(await readFile(objectFile, "utf8")));
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
          await atomicWrite(path.join(root, protectedPath), plaintext, 0o600);
          materialized.push(protectedPath);
        } finally {
          plaintext.fill(0);
        }
        console.log(`Unlocked ${protectedPath}`);
      } finally {
        key.fill(0);
      }
    }
  } catch (error) {
    for (const protectedPath of materialized) {
      await removeMaterializedFile(root, protectedPath).catch(() => undefined);
    }
    throw error;
  }
  try {
    await saveLease({
      root: path.resolve(root),
      server: policy.authServer,
      expiresAt: session.expiresAt,
      paths: materialized,
    });
  } catch (error) {
    for (const protectedPath of materialized) {
      await removeMaterializedFile(root, protectedPath).catch(() => undefined);
    }
    throw error;
  }
  return session;
}

export async function lock(root: string, logout = true): Promise<void> {
  const lease = await loadLease(root).catch(() => undefined);
  let server = lease?.server;
  let protectedPaths = lease?.paths;
  if (!server || !protectedPaths) {
    const policy = await loadEnclist(root);
    server = policy.authServer;
    protectedPaths = Object.keys(policy.files);
  }
  for (const protectedPath of protectedPaths) {
    await removeMaterializedFile(root, protectedPath);
    console.log(`Locked ${protectedPath}`);
  }
  await deleteLease(root);
  if (logout) {
    try {
      const session = await loadSession(server);
      await new AuthClient(server).logout(session).catch(() => undefined);
    } catch {
      // Local cleanup must still succeed if the service or session is unavailable.
    }
    await deleteSession(server);
  }
}

export async function lockIfSessionExpired(root: string, expectedExpiry: string): Promise<void> {
  const lease = await loadLease(root);
  let expiry = expectedExpiry;
  while (true) {
    const delay = Math.max(0, new Date(expiry).getTime() - Date.now() + 250);
    await new Promise((resolve) => setTimeout(resolve, delay));
    try {
      const current = await loadSession(lease.server);
      expiry = current.expiresAt;
    } catch {
      for (const protectedPath of lease.paths) {
        await removeMaterializedFile(root, protectedPath);
      }
      await deleteLease(root);
      return;
    }
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
