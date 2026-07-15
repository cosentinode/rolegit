import { createHash, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { lstat, mkdir, open, readFile, realpath, rename, rm, stat } from "node:fs/promises";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";

import { gitMetadataPath } from "./files.js";
import { normalizePlaintextPath } from "./paths.js";
import type { LocalSession, MaterializationLease, MaterializedFile } from "./types.js";

function roleGitHome(): string {
  const configured = process.env.ROLEGIT_HOME;
  if (configured !== undefined && !path.isAbsolute(configured)) {
    throw new Error("ROLEGIT_HOME must be an absolute path");
  }
  return path.resolve(configured ?? path.join(homedir(), ".config", "rolegit"));
}

function containedRelativePath(root: string, target: string): string | undefined {
  const relative = path.relative(root, target);
  if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) return undefined;
  return relative === "" ? "." : relative.split(path.sep).join("/");
}

export function roleGitMetadataPath(root: string): string | undefined {
  const resolvedRoot = path.resolve(root);
  const home = roleGitHome();
  const lexical = containedRelativePath(resolvedRoot, home);
  if (lexical !== undefined) return lexical;
  try {
    return containedRelativePath(realpathSync.native(resolvedRoot), realpathSync.native(home));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function pathNamesEqual(first: string, second: string): boolean {
  return process.platform === "win32"
    ? first.toLowerCase() === second.toLowerCase()
    : first === second;
}

async function rootsEqual(first: string, second: string): Promise<boolean> {
  const [firstReal, secondReal] = await Promise.all([realpath(first), realpath(second)]);
  if (pathNamesEqual(firstReal, secondReal)) return true;
  const [firstStat, secondStat] = await Promise.all([
    stat(firstReal, { bigint: true }),
    stat(secondReal, { bigint: true }),
  ]);
  return firstStat.ino !== 0n && firstStat.dev === secondStat.dev && firstStat.ino === secondStat.ino;
}

export function repositoryId(root: string): string {
  let marker: string;
  try {
    const prefix = execFileSync("git", ["rev-parse", "--show-prefix"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (prefix !== "") {
      return createHash("sha256").update(path.resolve(root)).digest("hex");
    }
    const gitPath = execFileSync("git", ["rev-parse", "--git-path", "rolegit-id"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    marker = path.resolve(root, gitPath);
  } catch {
    return createHash("sha256").update(path.resolve(root)).digest("hex");
  }
  try {
    const value = readFileSync(marker, "utf8").trim();
    if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(value)) throw new Error("invalid RoleGit checkout identity");
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  mkdirSync(path.dirname(marker), { recursive: true, mode: 0o700 });
  const value = randomUUID();
  try {
    writeFileSync(marker, `${value}\n`, { flag: "wx", mode: 0o600 });
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const existing = readFileSync(marker, "utf8").trim();
    if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(existing)) throw new Error("invalid RoleGit checkout identity");
    return existing;
  }
}

function sessionPath(root: string, server: string): string {
  const id = createHash("sha256").update(`${repositoryId(root)}\0${server}`).digest("hex");
  return path.join(roleGitHome(), "sessions", `${id}.json`);
}

function leasePath(root: string): string {
  const id = createHash("sha256").update(repositoryId(root)).digest("hex");
  return path.join(roleGitHome(), "leases", `${id}.json`);
}

function repositoryPath(root: string): string {
  const id = createHash("sha256").update(repositoryId(root)).digest("hex");
  return path.join(roleGitHome(), "repositories", `${id}.json`);
}

interface RepositoryMetadata {
  repositoryId: string;
  root: string;
  servers: string[];
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
      let parsed: Partial<LockOwner>;
      try {
        parsed = JSON.parse(await readFile(destination, "utf8")) as Partial<LockOwner>;
      } catch {
        try {
          if (Date.now() - (await lstat(destination)).mtimeMs < 100) {
            await new Promise((resolve) => setTimeout(resolve, 10));
            continue;
          }
        } catch {
          continue;
        }
        throw new Error(`invalid state lock ${destination}; verify no RoleGit process is using it before removal`);
      }
      if (typeof parsed.pid !== "number" || typeof parsed.token !== "string") {
        throw new Error(`invalid state lock ${destination}; verify no RoleGit process is using it before removal`);
      }
      if (!(await processIsAlive(parsed.pid))) {
        throw new Error(`stale state lock ${destination}; verify the owner exited before removal`);
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
  const id = repositoryId(root);
  return withStateLock(`${leasePath(root)}.operation.lock`, async () => {
    const currentRoot = await realpath(root);
    let metadata: RepositoryMetadata;
    try {
      metadata = await loadRepositoryMetadata(root);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      metadata = { repositoryId: id, root: currentRoot, servers: [] };
      await writePrivateJson(repositoryPath(root), metadata);
    }
    if (!pathNamesEqual(metadata.root, currentRoot)) {
      let duplicate = false;
      try {
        if (!(await rootsEqual(metadata.root, currentRoot))) {
          duplicate = repositoryId(metadata.root) === id;
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      if (duplicate) {
        throw new Error(
          `duplicate RoleGit checkout identity at ${metadata.root} and ${currentRoot}; ` +
          "do not use copied checkouts until one has a new identity",
        );
      }
      await writePrivateJson(repositoryPath(root), { ...metadata, root: currentRoot });
    }
    return operation();
  });
}

function withSessionLock<T>(root: string, server: string, operation: () => Promise<T>): Promise<T> {
  return withStateLock(`${sessionPath(root, server)}.lock`, operation);
}

export async function saveSessionUnlocked(root: string, session: LocalSession): Promise<void> {
  await withSessionLock(root, session.server, async () => {
    try {
      const existing = await loadSessionFile(root, session.server);
      if (sessionId(existing) !== sessionId(session)) {
        throw new Error("another session is active; run `rolegit lock` before logging in again");
      }
    } catch (error) {
      if (!/no RoleGit session|RoleGit session expired/.test((error as Error).message)) throw error;
    }
    await writePrivateJson(sessionPath(root, session.server), session);
  });
}

export function saveSession(root: string, session: LocalSession): Promise<void> {
  return withRepositoryLock(root, () => saveSessionUnlocked(root, session));
}

export async function saveRepositoryServerUnlocked(root: string, server: string): Promise<void> {
  let servers: string[] = [];
  try {
    servers = await loadRepositoryServers(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await writePrivateJson(repositoryPath(root), {
    repositoryId: repositoryId(root),
    root: await realpath(root),
    servers: [...new Set([...servers, server])],
  });
}

export function saveRepositoryServer(root: string, server: string): Promise<void> {
  return withRepositoryLock(root, () => saveRepositoryServerUnlocked(root, server));
}

async function loadRepositoryMetadata(root: string): Promise<RepositoryMetadata> {
  const source = repositoryPath(root);
  const repositoryStat = await lstat(source);
  if (repositoryStat.isSymbolicLink() || !repositoryStat.isFile()) {
    throw new Error("refusing non-regular repository session metadata");
  }
  const parsed = JSON.parse(await readFile(source, "utf8")) as {
    repositoryId?: unknown;
    root?: unknown;
    servers?: unknown;
  };
  if (
    parsed.repositoryId !== repositoryId(root) ||
    typeof parsed.root !== "string" || !path.isAbsolute(parsed.root) ||
    !Array.isArray(parsed.servers) ||
    !parsed.servers.every((server) => typeof server === "string")
  ) {
    throw new Error("invalid repository session metadata");
  }
  return parsed as RepositoryMetadata;
}

async function assertRepositoryRoot(root: string): Promise<void> {
  let metadata: RepositoryMetadata;
  try {
    metadata = await loadRepositoryMetadata(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  let matches = false;
  try {
    matches = await rootsEqual(metadata.root, root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (!matches) {
    throw new Error(`repository checkout identity is bound to another root (${metadata.root})`);
  }
}

export async function loadRepositoryServers(root: string): Promise<string[]> {
  const metadata = await loadRepositoryMetadata(root);
  if (!(await rootsEqual(metadata.root, root))) {
    throw new Error("repository checkout identity is bound to another root");
  }
  return metadata.servers;
}

async function loadSessionFile(root: string, server: string): Promise<LocalSession> {
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

export function loadSessionUnlocked(root: string, server: string): Promise<LocalSession> {
  return withSessionLock(root, server, () => loadSessionFile(root, server));
}

export function loadSession(root: string, server: string): Promise<LocalSession> {
  return withRepositoryLock(root, () => loadSessionUnlocked(root, server));
}

export async function deleteSessionUnlocked(
  root: string,
  server: string,
  expectedSessionId?: string,
): Promise<void> {
  await withSessionLock(root, server, async () => {
    if (expectedSessionId) {
      try {
        const current = await loadSessionFile(root, server);
        if (sessionId(current) !== expectedSessionId) return;
      } catch (error) {
        if (/no RoleGit session|RoleGit session expired/.test((error as Error).message)) return;
        throw error;
      }
    }
    await rm(sessionPath(root, server), { force: true });
  });
}

export function deleteSession(
  root: string,
  server: string,
  expectedSessionId?: string,
): Promise<void> {
  return withRepositoryLock(root, () => deleteSessionUnlocked(root, server, expectedSessionId));
}

export function sessionTimeRemaining(session: LocalSession): number {
  return Math.max(0, new Date(session.expiresAt).getTime() - Date.now());
}

export function sessionId(session: LocalSession): string {
  return createHash("sha256").update(session.token).digest("hex");
}

function normalizeMaterializedFile(value: unknown, root?: string): MaterializedFile {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("invalid materialization lease");
  }
  const file = value as Partial<MaterializedFile>;
  if (typeof file.path !== "string" || !/^[a-f0-9]{64}$/.test(file.digest ?? "")) {
    throw new Error("invalid materialization lease");
  }
  const protectedPath = normalizePlaintextPath(file.path);
  const metadataPaths = root === undefined
    ? []
    : [gitMetadataPath(root), roleGitMetadataPath(root)]
      .filter((entry): entry is string => entry !== undefined)
      .map((entry) => entry.toLowerCase());
  const portablePath = protectedPath.toLowerCase();
  if (metadataPaths.some((metadataPath) =>
    metadataPath === "." || portablePath === metadataPath || portablePath.startsWith(`${metadataPath}/`))) {
    throw new Error("materialization lease cannot contain repository metadata");
  }
  return { path: protectedPath, digest: file.digest! };
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
  for (const file of lease.paths.map((file) => normalizeMaterializedFile(file, lease.root))) {
    paths.set(file.path, file);
  }
  await writePrivateJson(leasePath(lease.root), { ...lease, paths: [...paths.values()] });
}

export async function replaceLeaseMaterializationsUnlocked(lease: MaterializationLease): Promise<void> {
  const current = await loadLease(lease.root);
  if (
    current.server !== lease.server ||
    current.userId !== lease.userId ||
    current.sessionId !== lease.sessionId
  ) {
    throw new Error("files are unlocked by a different session; run `rolegit lock` first");
  }
  const paths = new Map<string, MaterializedFile>();
  for (const file of lease.paths.map((entry) => normalizeMaterializedFile(entry, lease.root))) {
    paths.set(file.path, file);
  }
  if (paths.size === 0) {
    await deleteLeaseUnlocked(lease.root);
    return;
  }
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
  lease.paths[index] = normalizeMaterializedFile(file, root);
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
  await assertRepositoryRoot(root);
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
    lease.repositoryId !== repositoryId(root) ||
    typeof lease.root !== "string" ||
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
    paths: lease.paths.map((file) => normalizeMaterializedFile(file, root)),
  };
}

export async function deleteLeaseUnlocked(root: string): Promise<void> {
  await rm(leasePath(root), { force: true });
}

export function deleteLease(root: string): Promise<void> {
  return withRepositoryLock(root, () => deleteLeaseUnlocked(root));
}
