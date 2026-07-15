import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import { lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";

import { normalizePlaintextPath } from "./paths.js";
import type { MaterializedFile } from "./types.js";

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

function expectedGitNegative(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { status?: unknown }).status === 1;
}

function gitFailure(operation: string, error: unknown): never {
  const rawStderr = typeof error === "object" && error !== null
    ? (error as { stderr?: unknown }).stderr
    : undefined;
  const stderr = Buffer.isBuffer(rawStderr) || typeof rawStderr === "string"
    ? rawStderr.toString().trim()
    : "";
  throw new Error(`git ${operation} failed${stderr ? `: ${stderr}` : ""}`, { cause: error });
}

function portablePathspec(relativePath: string): string {
  return `:(icase,literal)${relativePath}`;
}

export function gitMetadataPath(root: string): string | undefined {
  let hasGitEntry = true;
  try {
    lstatSync(path.join(root, ".git"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    hasGitEntry = false;
  }
  if (!hasGitEntry && process.env.GIT_DIR === undefined && process.env.GIT_WORK_TREE === undefined) return undefined;
  let gitDirectory: string;
  try {
    gitDirectory = execFileSync("git", ["rev-parse", "--absolute-git-dir"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    gitFailure("rev-parse", error);
  }
  const canonicalRoot = realpathSync.native(root);
  const canonicalGitDirectory = realpathSync.native(gitDirectory);
  const relative = path.relative(canonicalRoot, canonicalGitDirectory);
  if (relative === "") return ".";
  if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) return undefined;
  return relative.split(path.sep).join("/");
}

export async function existingPortablePathAlias(root: string, relativePath: string): Promise<string | undefined> {
  const components = relativePath.split("/");
  const actual: string[] = [];
  let current = root;
  for (const component of components) {
    let entries: string[];
    try {
      entries = await readdir(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
    const matches = entries.filter((entry) => entry.toLowerCase() === component.toLowerCase());
    const alias = matches.find((entry) => entry !== component);
    if (alias !== undefined) return [...actual, alias, ...components.slice(actual.length + 1)].join("/");
    if (!matches.includes(component)) return undefined;
    actual.push(component);
    current = path.join(current, component);
  }
  return undefined;
}

export function gitPathIsTracked(root: string, relativePath: string): boolean {
  try {
    execFileSync("git", ["ls-files", "--error-unmatch", "--", portablePathspec(relativePath)], {
      cwd: root,
      stdio: ["ignore", "ignore", "pipe"],
    });
    return true;
  } catch (error) {
    if (expectedGitNegative(error)) return false;
    gitFailure("ls-files", error);
  }
}

export function gitPathIsIgnored(root: string, relativePath: string): boolean {
  try {
    execFileSync("git", ["-c", "core.ignorecase=true", "check-ignore", "--quiet", "--", relativePath], {
      cwd: root,
      stdio: ["ignore", "ignore", "pipe"],
    });
    return true;
  } catch (error) {
    if (expectedGitNegative(error)) return false;
    gitFailure("check-ignore", error);
  }
}

export function gitPathExistsInHistory(root: string, relativePath: string): boolean {
  try {
    const output = execFileSync(
      "git",
      ["log", "--all", "--format=%H", "--", portablePathspec(relativePath)],
      {
        cwd: root,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return output.trim().length > 0;
  } catch (error) {
    gitFailure("log", error);
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
  const escapedPath = Array.from(relativePath, (character) => {
    if (character === "/") return character;
    const variants = [...new Set([character, character.toLowerCase(), character.toUpperCase()])];
    if (variants.length > 1 && variants.every((variant) => Array.from(variant).length === 1)) {
      return `[${variants.map((variant) => variant.replaceAll(/([\\\]\-^])/g, "\\$1")).join("")}]`;
    }
    return character.replaceAll(/([\\*?\[\]!#])/g, "\\$1");
  }).join("");
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

export function materializationDigest(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export async function writeMaterializedFile(
  root: string,
  relativePath: string,
  data: Buffer,
): Promise<void> {
  const normalized = normalizePlaintextPath(relativePath);
  await assertNoSymlinkPath(root, normalized);
  const destination = path.join(root, normalized);
  await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  let handle;
  try {
    handle = await open(destination, "wx", 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = undefined;
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (handle) await rm(destination, { force: true }).catch(() => undefined);
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`refusing to materialize ${normalized}: destination already exists`, { cause: error });
    }
    throw error;
  }
}

export async function removeMaterializedFile(root: string, file: MaterializedFile): Promise<void> {
  const normalized = normalizePlaintextPath(file.path);
  await assertNoSymlinkPath(root, normalized);
  const destination = path.join(root, normalized);
  let destinationStat;
  try {
    destinationStat = await lstat(destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!destinationStat.isFile()) {
    throw new Error(`refusing to remove changed materialized path ${normalized}`);
  }
  const content = await readFile(destination);
  try {
    if (materializationDigest(content) !== file.digest) {
      throw new Error(`refusing to remove modified materialized file ${normalized}`);
    }
  } finally {
    content.fill(0);
  }
  await rm(destination);
}
