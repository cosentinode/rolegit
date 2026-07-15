import { execFileSync } from "node:child_process";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";

import { normalizeProtectedPath } from "./paths.js";

export function repositoryRoot(cwd = process.cwd()): string {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    throw new Error("current directory is not inside a Git repository");
  }
}

export function gitPathIsTracked(root: string, relativePath: string): boolean {
  try {
    execFileSync("git", ["ls-files", "--error-unmatch", "--", relativePath], {
      cwd: root,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

export function gitPathIsIgnored(root: string, relativePath: string): boolean {
  try {
    execFileSync("git", ["check-ignore", "--quiet", "--", relativePath], {
      cwd: root,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

export function gitPathExistsInHistory(root: string, relativePath: string): boolean {
  try {
    const output = execFileSync("git", ["log", "--all", "--format=%H", "--", relativePath], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return output.trim().length > 0;
  } catch {
    return false;
  }
}

export async function appendGitIgnore(root: string, relativePath: string): Promise<void> {
  const ignorePath = path.join(root, ".gitignore");
  let content = "";
  try {
    const ignoreStat = await lstat(ignorePath);
    if (ignoreStat.isSymbolicLink() || !ignoreStat.isFile()) {
      throw new Error("refusing non-regular .gitignore");
    }
    content = await readFile(ignorePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const escapedPath = relativePath.replaceAll(/([\\*?\[\]!#])/g, "\\$1");
  const lines = [`/${escapedPath}`, `/${escapedPath}.rolegit-*.tmp`];
  const existing = new Set(content.split(/\r?\n/));
  const additions = lines.filter((line) => !existing.has(line));
  if (additions.length === 0) return;
  const separator = content.length > 0 && !content.endsWith("\n") ? "\n" : "";
  await atomicWrite(ignorePath, Buffer.from(`${content}${separator}${additions.join("\n")}\n`), 0o644);
}

export async function assertNoSymlinkPath(root: string, relativePath: string): Promise<void> {
  const segments = relativePath.split("/");
  let current = root;
  for (const segment of segments) {
    current = path.join(current, segment);
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) throw new Error(`refusing symbolic-link path: ${relativePath}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
  }
}

export async function atomicWrite(destination: string, data: Buffer, mode: number): Promise<void> {
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.rolegit-${process.pid}-${Date.now()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, "wx", mode);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function removeMaterializedFile(root: string, relativePath: string): Promise<void> {
  const normalized = normalizeProtectedPath(relativePath);
  await assertNoSymlinkPath(root, normalized);
  await rm(path.join(root, normalized), { force: true });
}
