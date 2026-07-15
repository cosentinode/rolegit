import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";

import { normalizeProtectedPath } from "./paths.js";
import type { LocalSession, MaterializationLease, MaterializedFile } from "./types.js";

function roleGitHome(): string {
  return process.env.ROLEGIT_HOME ?? path.join(homedir(), ".config", "rolegit");
}

function sessionPath(root: string, server: string): string {
  const id = createHash("sha256").update(`${path.resolve(root)}\0${server}`).digest("hex");
  return path.join(roleGitHome(), "sessions", `${id}.json`);
}

function leasePath(root: string): string {
  const id = createHash("sha256").update(path.resolve(root)).digest("hex");
  return path.join(roleGitHome(), "leases", `${id}.json`);
}

function repositoryPath(root: string): string {
  const id = createHash("sha256").update(path.resolve(root)).digest("hex");
  return path.join(roleGitHome(), "repositories", `${id}.json`);
}

async function writePrivateJson(destination: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.${process.pid}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
    await handle.close();
    await rename(temporary, destination);
  } catch (error) {
    await handle.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

interface LockOwner {
  pid: number;
  token: string;
  createdAt: number;
}

async function processIsAlive(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function withStateLock<T>(destination: string, operation: () => Promise<T>): Promise<T> {
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const owner: LockOwner = { pid: process.pid, token: randomUUID(), createdAt: Date.now() };
  const deadline = Date.now() + 30_000;
  let handle;
  while (!handle) {
    try {
      handle = await open(destination, "wx", 0o600);
      await handle.writeFile(JSON.stringify(owner));
      await handle.sync();
    } catch (error) {
      const acquired = handle !== undefined;
      await handle?.close().catch(() => undefined);
      handle = undefined;
      if (acquired) await rm(destination, { force: true }).catch(() => undefined);
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      let stale = false;
      try {
        const lockStat = await lstat(destination);
        const parsed = JSON.parse(await readFile(destination, "utf8")) as Partial<LockOwner>;
        stale =
          typeof parsed.pid === "number" &&
          typeof parsed.createdAt === "number" &&
          (!(await processIsAlive(parsed.pid)) || Date.now() - parsed.createdAt > 3_600_000);
        if (!stale && Date.now() - lockStat.mtimeMs > 5_000 && typeof parsed.pid !== "number") stale = true;
      } catch {
        // A new owner may still be writing; retry until it is readable or old enough to reclaim.
      }
      if (stale) {
        await rm(destination, { force: true });
        continue;
      }
      if (Date.now() >= deadline) throw new Error(`timed out waiting for state lock ${destination}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  try {
    return await operation();
  } finally {
    await handle.close().catch(() => undefined);
    try {
      const current = JSON.parse(await readFile(destination, "utf8")) as Partial<LockOwner>;
      if (current.token === owner.token) await rm(destination, { force: true });
    } catch {
      // A missing or replaced lock is not owned by this operation.
    }
  }
}

export function withRepositoryLock<T>(root: string, operation: () => Promise<T>): Promise<T> {
  return withStateLock(`${leasePath(root)}.operation.lock`, operation);
}

function withSessionLock<T>(root: string, server: string, operation: () => Promise<T>): Promise<T> {
  return withStateLock(`${sessionPath(root, server)}.lock`, operation);
}

export async function saveSession(root: string, session: LocalSession): Promise<void> {
  await withSessionLock(root, session.server, async () => {
    try {
      const existing = await loadSessionUnlocked(root, session.server);
      if (sessionId(existing) !== sessionId(session)) {
        throw new Error("another session is active; run `rolegit lock` before logging in again");
      }
    } catch (error) {
      if (!/no RoleGit session|RoleGit session expired/.test((error as Error).message)) throw error;
    }
    await writePrivateJson(sessionPath(root, session.server), session);
  });
}

export async function saveRepositoryServer(root: string, server: string): Promise<void> {
  await writePrivateJson(repositoryPath(root), { root: path.resolve(root), server });
}

export async function loadRepositoryServer(root: string): Promise<string> {
  const source = repositoryPath(root);
  const repositoryStat = await lstat(source);
  if (repositoryStat.isSymbolicLink() || !repositoryStat.isFile()) {
    throw new Error("refusing non-regular repository session metadata");
  }
  const parsed = JSON.parse(await readFile(source, "utf8")) as { root?: unknown; server?: unknown };
  if (parsed.root !== path.resolve(root) || typeof parsed.server !== "string") {
    throw new Error("invalid repository session metadata");
  }
  return parsed.server;
}

async function loadSessionUnlocked(root: string, server: string): Promise<LocalSession> {
  let parsed: unknown;
  try {
    const source = sessionPath(root, server);
    const sessionStat = await lstat(source);
    if (sessionStat.isSymbolicLink() || !sessionStat.isFile()) {
      throw new Error("refusing non-regular local session file");
    }
    parsed = JSON.parse(await readFile(source, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("no RoleGit session; run `rolegit login` first");
    }
    throw error;
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("invalid local session");
  const session = parsed as Partial<LocalSession>;
  if (
    session.server !== server ||
    typeof session.token !== "string" ||
    typeof session.expiresAt !== "string" ||
    typeof session.user?.id !== "number" ||
    typeof session.user.login !== "string"
  ) {
    throw new Error("invalid local session");
  }
  const expiresAt = new Date(session.expiresAt).getTime();
  if (!Number.isFinite(expiresAt)) throw new Error("invalid local session expiration");
  if (expiresAt <= Date.now()) {
    await rm(sessionPath(root, server), { force: true });
    throw new Error("RoleGit session expired; run `rolegit login` again");
  }
  return session as LocalSession;
}

export function loadSession(root: string, server: string): Promise<LocalSession> {
  return withSessionLock(root, server, () => loadSessionUnlocked(root, server));
}

export async function deleteSession(
  root: string,
  server: string,
  expectedSessionId?: string,
): Promise<void> {
  await withSessionLock(root, server, async () => {
    if (expectedSessionId) {
      try {
        const current = await loadSessionUnlocked(root, server);
        if (sessionId(current) !== expectedSessionId) return;
      } catch (error) {
        if (/no RoleGit session|RoleGit session expired/.test((error as Error).message)) return;
        throw error;
      }
    }
    await rm(sessionPath(root, server), { force: true });
  });
}

export function sessionTimeRemaining(session: LocalSession): number {
  return Math.max(0, new Date(session.expiresAt).getTime() - Date.now());
}

export function sessionId(session: LocalSession): string {
  return createHash("sha256").update(session.token).digest("hex");
}

function normalizeMaterializedFile(value: unknown): MaterializedFile {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid materialization lease");
  }
  const file = value as Partial<MaterializedFile>;
  if (typeof file.path !== "string" || !/^[a-f0-9]{64}$/.test(file.digest ?? "")) {
    throw new Error("invalid materialization lease");
  }
  return { path: normalizeProtectedPath(file.path), digest: file.digest! };
}

export async function saveLeaseUnlocked(lease: MaterializationLease): Promise<void> {
    let existing: MaterializationLease | undefined;
    try {
      existing = await loadLease(lease.root);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (existing) {
      if (
        existing.server !== lease.server ||
        existing.userId !== lease.userId ||
        existing.sessionId !== lease.sessionId
      ) {
        throw new Error("files are unlocked by a different session; run `rolegit lock` first");
      }
    }
    const paths = new Map(existing?.paths.map((file) => [file.path, file]));
    for (const file of lease.paths.map(normalizeMaterializedFile)) paths.set(file.path, file);
    await writePrivateJson(leasePath(lease.root), { ...lease, paths: [...paths.values()] });
}

export function saveLease(lease: MaterializationLease): Promise<void> {
  return withRepositoryLock(lease.root, () => saveLeaseUnlocked(lease));
}

export async function refreshLeaseMaterializationUnlocked(
  root: string,
  session: LocalSession,
  file: MaterializedFile,
): Promise<void> {
  let lease: MaterializationLease;
  try {
    lease = await loadLease(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const index = lease.paths.findIndex((entry) => entry.path === file.path);
  if (index === -1) return;
  if (
    lease.server !== session.server ||
    lease.userId !== session.user.id ||
    lease.sessionId !== sessionId(session)
  ) {
    throw new Error("materialized file belongs to a different session; run `rolegit lock` first");
  }
  lease.paths[index] = normalizeMaterializedFile(file);
  lease.expiresAt = session.expiresAt;
  await writePrivateJson(leasePath(root), lease);
}

export function refreshLeaseMaterialization(
  root: string,
  session: LocalSession,
  file: MaterializedFile,
): Promise<void> {
  return withRepositoryLock(root, () => refreshLeaseMaterializationUnlocked(root, session, file));
}

export async function loadLease(root: string): Promise<MaterializationLease> {
  const source = leasePath(root);
  const leaseStat = await lstat(source);
  if (leaseStat.isSymbolicLink() || !leaseStat.isFile()) {
    throw new Error("refusing non-regular materialization lease");
  }
  const parsed: unknown = JSON.parse(await readFile(source, "utf8"));
  if (typeof parsed !== "object" || parsed === null) throw new Error("invalid materialization lease");
  const lease = parsed as Partial<MaterializationLease>;
  if (
    lease.version !== 1 ||
    lease.root !== path.resolve(root) ||
    typeof lease.server !== "string" ||
    typeof lease.expiresAt !== "string" ||
    !Number.isSafeInteger(lease.userId) ||
    (lease.userId ?? 0) <= 0 ||
    !/^[a-f0-9]{64}$/.test(lease.sessionId ?? "") ||
    !Array.isArray(lease.paths) ||
    !Number.isFinite(new Date(lease.expiresAt).getTime())
  ) throw new Error("invalid materialization lease");
  return {
    ...(lease as MaterializationLease),
    paths: lease.paths.map(normalizeMaterializedFile),
  };
}

export async function deleteLease(root: string): Promise<void> {
  await rm(leasePath(root), { force: true });
}
