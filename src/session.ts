import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";

import type { LocalSession, MaterializationLease } from "./types.js";

function roleGitHome(): string {
  return process.env.ROLEGIT_HOME ?? path.join(homedir(), ".config", "rolegit");
}

function sessionPath(server: string): string {
  const id = createHash("sha256").update(server).digest("hex");
  return path.join(roleGitHome(), "sessions", `${id}.json`);
}

function leasePath(root: string): string {
  const id = createHash("sha256").update(path.resolve(root)).digest("hex");
  return path.join(roleGitHome(), "leases", `${id}.json`);
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

export async function saveSession(session: LocalSession): Promise<void> {
  await writePrivateJson(sessionPath(session.server), session);
}

export async function loadSession(server: string): Promise<LocalSession> {
  let parsed: unknown;
  try {
    const source = sessionPath(server);
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
    await deleteSession(server);
    throw new Error("RoleGit session expired; run `rolegit login` again");
  }
  return session as LocalSession;
}

export async function deleteSession(server: string): Promise<void> {
  await rm(sessionPath(server), { force: true });
}

export function sessionTimeRemaining(session: LocalSession): number {
  return Math.max(0, new Date(session.expiresAt).getTime() - Date.now());
}

export async function saveLease(lease: MaterializationLease): Promise<void> {
  let paths = lease.paths;
  const existing = await loadLease(lease.root).catch(() => undefined);
  if (existing && existing.server !== lease.server) {
    throw new Error("authorization server changed while files are unlocked; run `rolegit lock` first");
  }
  if (existing) {
    paths = [...new Set([...existing.paths, ...paths])];
  }
  await writePrivateJson(leasePath(lease.root), { ...lease, paths });
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
    lease.root !== path.resolve(root) ||
    typeof lease.server !== "string" ||
    typeof lease.expiresAt !== "string" ||
    !Array.isArray(lease.paths) ||
    !lease.paths.every((entry) => typeof entry === "string")
  ) throw new Error("invalid materialization lease");
  return lease as MaterializationLease;
}

export async function deleteLease(root: string): Promise<void> {
  await rm(leasePath(root), { force: true });
}
