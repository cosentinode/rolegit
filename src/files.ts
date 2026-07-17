import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";

import { normalizePlaintextPath, portablePathKey } from "./paths.js";
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

function listedGitPaths(root: string, args: string[], operation: string): string[] {
  try {
    return execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).split("\0").filter((entry) => entry.length > 0);
  } catch (error) {
    gitFailure(operation, error);
  }
}

function realpathWithMissingSuffix(target: string): string {
  let existing = target;
  const suffix: string[] = [];
  while (true) {
    try {
      return path.join(realpathSync.native(existing), ...suffix);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = path.dirname(existing);
      if (parent === existing) throw error;
      suffix.unshift(path.basename(existing));
      existing = parent;
    }
  }
}

function worktreeMetadataPath(root: string, candidate: string): string | undefined {
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(root, candidate);
  const lexical = path.relative(resolvedRoot, resolvedCandidate);
  if (lexical === "") return ".";
  if (!path.isAbsolute(lexical) && lexical !== ".." && !lexical.startsWith(`..${path.sep}`)) {
    return lexical.split(path.sep).join("/");
  }
  const relative = path.relative(realpathSync.native(resolvedRoot), realpathWithMissingSuffix(resolvedCandidate));
  if (relative === "") return ".";
  if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) return undefined;
  return relative.split(path.sep).join("/");
}

function gitPath(root: string, args: string[]): string {
  try {
    return execFileSync("git", ["rev-parse", ...args], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    gitFailure(`rev-parse ${args.join(" ")}`, error);
  }
}

function parseGitAlternates(value: string, separator: string): string[] {
  const entries: string[] = [];
  let offset = 0;
  while (offset < value.length) {
    const end = value.indexOf(separator, offset);
    const entryEnd = end === -1 ? value.length : end;
    if (value[offset] === "#") {
      offset = entryEnd + 1;
      continue;
    }
    if (value[offset] !== "\"") {
      const entry = value.slice(offset, entryEnd);
      if (entry.includes("\0")) throw new Error("malformed Git alternate object configuration");
      if (entry.length > 0) entries.push(entry);
      offset = entryEnd + 1;
      continue;
    }

    let entry = "";
    let index = offset + 1;
    for (; index < value.length && value[index] !== "\""; index += 1) {
      const character = value[index]!;
      if (character !== "\\") {
        entry += character;
        continue;
      }
      const escaped = value[++index];
      const escapes: Record<string, string> = {
        a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "\"": "\"",
      };
      if (escaped !== undefined && Object.hasOwn(escapes, escaped)) {
        entry += escapes[escaped];
        continue;
      }
      const octal = value.slice(index, index + 3);
      if (!/^[0-3][0-7]{2}$/.test(octal)) throw new Error("malformed Git alternate object configuration");
      entry += String.fromCharCode(Number.parseInt(octal, 8));
      index += 2;
    }
    if (index >= value.length || (index + 1 < value.length && value[index + 1] !== separator)) {
      throw new Error("malformed Git alternate object configuration");
    }
    if (entry.includes("\0")) throw new Error("malformed Git alternate object configuration");
    if (entry.length > 0) entries.push(entry);
    offset = index + 2;
  }
  return entries;
}

function gitAlternateObjectPaths(root: string, objectDirectory: string): string[] {
  const candidates: string[] = [];
  const pending = [{ candidate: objectDirectory, required: false }];
  if (process.env.GIT_ALTERNATE_OBJECT_DIRECTORIES) {
    pending.push(...parseGitAlternates(process.env.GIT_ALTERNATE_OBJECT_DIRECTORIES, path.delimiter)
      .map((candidate) => ({ candidate: path.resolve(root, candidate), required: true })));
  }
  const visited = new Set<string>();
  while (pending.length > 0) {
    const { candidate, required } = pending.shift()!;
    const absolute = path.resolve(root, candidate);
    const resolved = realpathWithMissingSuffix(absolute);
    candidates.push(absolute);
    if (visited.has(resolved)) continue;
    visited.add(resolved);
    try {
      if (!lstatSync(resolved).isDirectory()) throw new Error("not a directory");
    } catch (error) {
      if (!required && (error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new Error(`invalid Git alternate object directory: ${absolute}`, { cause: error });
    }
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true })
        .decode(readFileSync(path.join(resolved, "info", "alternates")));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw new Error(`cannot read Git alternate object configuration: ${resolved}`, { cause: error });
    }
    pending.push(...parseGitAlternates(content, "\n")
      .map((entry) => ({ candidate: path.resolve(resolved, entry), required: true })));
  }
  return candidates;
}

export function gitMetadataPaths(root: string): string[] {
  let hasGitEntry = true;
  try {
    lstatSync(path.join(root, ".git"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    hasGitEntry = false;
  }
  if (!hasGitEntry && process.env.GIT_DIR === undefined && process.env.GIT_WORK_TREE === undefined) return [];
  const objectDirectory = gitPath(root, ["--git-path", "objects"]);
  const candidates = [
    gitPath(root, ["--absolute-git-dir"]),
    gitPath(root, ["--git-common-dir"]),
    gitPath(root, ["--git-path", "index"]),
    ...gitAlternateObjectPaths(root, objectDirectory),
    gitPath(root, ["--git-path", "shallow"]),
    gitPath(root, ["--git-path", "info/grafts"]),
  ];
  for (const name of [
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_SHALLOW_FILE",
    "GIT_GRAFT_FILE",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
  ]) {
    const value = process.env[name];
    if (value) candidates.push(value);
  }
  return [...new Set(candidates
    .map((candidate) => worktreeMetadataPath(root, candidate))
    .filter((entry): entry is string => entry !== undefined))];
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
    const matches = entries.filter((entry) => portablePathKey(entry) === portablePathKey(component));
    const alias = matches.find((entry) => entry !== component);
    if (alias !== undefined) return [...actual, alias, ...components.slice(actual.length + 1)].join("/");
    if (!matches.includes(component)) return undefined;
    actual.push(component);
    current = path.join(current, component);
  }
  return undefined;
}

export function gitPathIsTracked(root: string, relativePath: string): boolean {
  const portablePath = portablePathKey(relativePath);
  return listedGitPaths(root, ["ls-files", "-z"], "ls-files")
    .some((entry) => portablePathKey(entry) === portablePath);
}

export function gitPathIsIgnored(root: string, relativePath: string): boolean {
  try {
    execFileSync("git", ["-c", "core.ignorecase=true", "check-ignore", "--quiet", "--", relativePath], {
      cwd: root,
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch (error) {
    if (expectedGitNegative(error)) return false;
    gitFailure("check-ignore", error);
  }
  const portablePath = portablePathKey(relativePath);
  const unignored = listedGitPaths(
    root,
    ["ls-files", "--others", "--exclude-standard", "-z"],
    "ls-files --others",
  );
  return !unignored.some((entry) => portablePathKey(entry) === portablePath);
}

export function gitPathExistsInHistory(root: string, relativePath: string): boolean {
  const portablePath = portablePathKey(relativePath);
  return listedGitPaths(
    root,
    ["-c", "core.quotePath=false", "log", "--all", "--format=", "--name-only", "--no-renames", "-z"],
    "log",
  ).some((entry) => portablePathKey(entry) === portablePath);
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
  const alternatives = portableIgnoreAlternatives(relativePath);
  const lines = alternatives.flatMap((escapedPath) => [`/${escapedPath}`, `/${escapedPath}.rolegit-*.tmp`]);
  const existing = new Set(content.split(/\r?\n/));
  const additions = lines.filter((line) => !existing.has(line));
  if (additions.length === 0) return;
  const separator = content.length > 0 && !content.endsWith("\n") ? "\n" : "";
  await atomicWrite(ignorePath, Buffer.from(`${content}${separator}${additions.join("\n")}\n`), 0o644);
}

let portableCaseVariants: Map<string, string[]> | undefined;

function caseVariants(): Map<string, string[]> {
  if (portableCaseVariants) return portableCaseVariants;
  // Git wildmatch classes are byte-oriented for non-ASCII, so collect aliases for complete patterns.
  portableCaseVariants = new Map<string, string[]>();
  for (let codePoint = 0; codePoint <= 0x10ffff; codePoint += 1) {
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) continue;
    const character = String.fromCodePoint(codePoint);
    const upper = character.toUpperCase();
    const folded = Array.from(upper).length === 1 ? upper.toLowerCase() : character;
    if (
      character.normalize("NFC") === character &&
      upper === character &&
      folded === character
    ) continue;
    const key = portablePathKey(character);
    if (Array.from(key).length !== 1) continue;
    const variants = portableCaseVariants.get(key) ?? [];
    variants.push(character);
    portableCaseVariants.set(key, variants);
  }
  return portableCaseVariants;
}

function escapeIgnoreLiteral(value: string): string {
  return value.replaceAll(/([\\*?\[\]!#])/g, "\\$1");
}

function portableIgnoreAlternatives(relativePath: string): string[] {
  const classes = caseVariants();
  let alternatives = [""];
  for (const character of relativePath) {
    if (character === "/") {
      alternatives = alternatives.map((entry) => `${entry}/`);
      continue;
    }
    const variants = classes.get(portablePathKey(character)) ?? [character];
    const ascii = variants.filter((variant) => /^[\x00-\x7f]$/.test(variant));
    const unicode = variants.filter((variant) => !/^[\x00-\x7f]$/.test(variant));
    const rawChoices = [
      ...(ascii.length > 1
        ? [`[${ascii.map((variant) => variant.replaceAll(/([\\\]\-^])/g, "\\$1")).join("")}]`]
        : ascii.map(escapeIgnoreLiteral)),
      ...unicode.map(escapeIgnoreLiteral),
    ];
    const choices = [...new Set(rawChoices.flatMap((choice) => [choice.normalize("NFC"), choice.normalize("NFD")]))];
    if (alternatives.length * choices.length > 1024) {
      throw new Error(`protected path has too many portable Unicode case aliases: ${relativePath}`);
    }
    alternatives = alternatives.flatMap((entry) => choices.map((choice) => `${entry}${choice}`));
  }
  const normalized = [...new Set(alternatives.flatMap((entry) => [
    entry,
    entry.normalize("NFC"),
    entry.normalize("NFD"),
  ]))];
  if (normalized.length > 1024) {
    throw new Error(`protected path has too many portable Unicode case aliases: ${relativePath}`);
  }
  return normalized;
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

export async function assertSingleLinkPath(root: string, relativePath: string): Promise<void> {
  try {
    const pathStat = await lstat(path.join(root, relativePath));
    if (pathStat.isFile() && pathStat.nlink > 1) {
      throw new Error(`refusing multiply-linked plaintext path: ${relativePath}`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
}

export async function syncDirectory(directory: string): Promise<void> {
  if (process.platform === "win32") return;
  const handle = await open(directory, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function ensureDurableDirectory(directory: string): Promise<void> {
  const resolved = path.resolve(directory);
  const firstCreated = await mkdir(resolved, { recursive: true, mode: 0o700 });
  if (firstCreated === undefined || process.platform === "win32") return;
  let current = path.resolve(firstCreated);
  await syncDirectory(path.dirname(current));
  for (const segment of path.relative(current, resolved).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    await syncDirectory(path.dirname(current));
  }
}

export async function atomicWrite(destination: string, data: Buffer, mode: number): Promise<void> {
  const directory = path.dirname(destination);
  await ensureDurableDirectory(directory);
  const temporary = `${destination}.rolegit-${process.pid}-${Date.now()}.tmp`;
  let handle;
  try {
    handle = await open(temporary, "wx", mode);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
    await syncDirectory(directory);
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
  const directory = path.dirname(destination);
  await ensureDurableDirectory(directory);
  let handle;
  try {
    handle = await open(destination, "wx", 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectory(directory);
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
  if (destinationStat.nlink > 1) {
    throw new Error(`refusing to remove multiply-linked materialized path ${normalized}`);
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
  await syncDirectory(path.dirname(destination));
}
