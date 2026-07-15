import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import type {
  AccessRule,
  DevelopmentUser,
  Enclist,
  EnclistFile,
  ServerPolicy,
  TeamRule,
} from "./types.js";
import { atomicWrite, gitMetadataPath } from "./files.js";
import { normalizePlaintextPath, normalizeProtectedPath } from "./paths.js";
import { roleGitMetadataPath } from "./session.js";

export { normalizePlaintextPath, normalizeProtectedPath } from "./paths.js";

export const ENCLIST_NAME = ".enclist";
export const MAX_SESSION_MINUTES = 365 * 24 * 60;

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value as number;
}

export function encryptedObjectPath(protectedPath: string): string {
  const digest = createHash("sha256").update(protectedPath).digest("hex");
  return `.rolegit/vault/${digest}.json`;
}

export function createEnclist(authServer: string): Enclist {
  validateAuthServer(authServer);
  return { version: 1, vaultId: randomUUID(), authServer, files: Object.create(null) as Enclist["files"] };
}

export function validateAuthServer(value: string): void {
  const url = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("authorization server must use HTTPS unless it is on loopback");
  }
}

export function parseEnclist(value: unknown): Enclist {
  const root = object(value, ENCLIST_NAME);
  if (root.version !== 1) throw new Error("unsupported .enclist version");
  const vaultId = string(root.vaultId, "vaultId");
  const authServer = string(root.authServer, "authServer");
  validateAuthServer(authServer);
  const rawFiles = object(root.files, "files");
  const files: Record<string, EnclistFile> = Object.create(null) as Record<string, EnclistFile>;
  const portablePaths = new Map<string, string>();
  for (const [rawPath, rawFile] of Object.entries(rawFiles)) {
    const protectedPath = normalizePlaintextPath(rawPath);
    if (Object.hasOwn(files, protectedPath)) throw new Error(`duplicate protected path: ${protectedPath}`);
    const portablePath = protectedPath.toLowerCase();
    const alias = portablePaths.get(portablePath);
    if (alias !== undefined && alias !== protectedPath) {
      throw new Error(`protected paths differ only by case: ${alias}, ${protectedPath}`);
    }
    portablePaths.set(portablePath, protectedPath);
    const file = object(rawFile, `files.${protectedPath}`);
    const objectPath = normalizeProtectedPath(string(file.object, `files.${protectedPath}.object`));
    if (objectPath !== encryptedObjectPath(protectedPath)) {
      throw new Error(`encrypted object for ${protectedPath} must use its canonical vault path`);
    }
    files[protectedPath] = { object: objectPath };
  }
  return { version: 1, vaultId, authServer, files };
}

function assertNoRepositoryMetadataFiles(root: string, policy: Enclist): void {
  const metadataPaths = [gitMetadataPath(root), roleGitMetadataPath(root)]
    .filter((entry): entry is string => entry !== undefined)
    .map((entry) => entry.toLowerCase());
  for (const protectedPath of Object.keys(policy.files)) {
    const portablePath = protectedPath.toLowerCase();
    if (metadataPaths.some((metadataPath) =>
      metadataPath === "." || portablePath === metadataPath || portablePath.startsWith(`${metadataPath}/`))) {
      throw new Error(`repository metadata cannot be protected: ${protectedPath}`);
    }
  }
}

export async function loadEnclist(root: string): Promise<Enclist> {
  const policyPath = path.join(root, ENCLIST_NAME);
  const policyStat = await lstat(policyPath);
  if (policyStat.isSymbolicLink() || !policyStat.isFile()) {
    throw new Error("refusing non-regular .enclist");
  }
  const content = await readFile(policyPath, "utf8");
  const policy = parseEnclist(JSON.parse(content));
  assertNoRepositoryMetadataFiles(root, policy);
  return policy;
}

export async function saveEnclist(root: string, policy: Enclist): Promise<void> {
  const policyPath = path.join(root, ENCLIST_NAME);
  try {
    const policyStat = await lstat(policyPath);
    if (policyStat.isSymbolicLink() || !policyStat.isFile()) {
      throw new Error("refusing non-regular .enclist");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const validated = parseEnclist(policy);
  assertNoRepositoryMetadataFiles(root, validated);
  await atomicWrite(policyPath, Buffer.from(`${JSON.stringify(validated, null, 2)}\n`), 0o644);
}

function parseTeam(value: unknown, label: string): TeamRule {
  const team = object(value, label);
  return {
    organization: string(team.organization, `${label}.organization`),
    slug: string(team.slug, `${label}.slug`),
  };
}

function parseAccessRule(value: unknown, label: string): AccessRule {
  const rule = object(value, label);
  if (!Array.isArray(rule.users) || !Array.isArray(rule.teams)) {
    throw new Error(`${label} must contain users and teams arrays`);
  }
  const users = rule.users.map((id, index) => positiveInteger(id, `${label}.users[${index}]`));
  const teams = rule.teams.map((team, index) => parseTeam(team, `${label}.teams[${index}]`));
  if (users.length === 0 && teams.length === 0) {
    throw new Error(`${label} must authorize at least one user or team`);
  }
  return { users, teams };
}

export function parseServerPolicy(value: unknown): ServerPolicy {
  const root = object(value, "server policy");
  if (root.version !== 1) throw new Error("unsupported server policy version");
  const rawVaults = object(root.vaults, "vaults");
  const vaults: ServerPolicy["vaults"] = Object.create(null) as ServerPolicy["vaults"];
  for (const [vaultId, rawVault] of Object.entries(rawVaults)) {
    const vault = object(rawVault, `vaults.${vaultId}`);
    const rawFiles = object(vault.files, `vaults.${vaultId}.files`);
    const files: Record<string, AccessRule> = Object.create(null) as Record<string, AccessRule>;
    const portablePaths = new Map<string, string>();
    for (const [rawPath, rawRule] of Object.entries(rawFiles)) {
      const protectedPath = normalizePlaintextPath(rawPath);
      if (Object.hasOwn(files, protectedPath)) throw new Error(`duplicate protected path: ${protectedPath}`);
      const portablePath = protectedPath.toLowerCase();
      const alias = portablePaths.get(portablePath);
      if (alias !== undefined && alias !== protectedPath) {
        throw new Error(`protected paths differ only by case: ${alias}, ${protectedPath}`);
      }
      portablePaths.set(portablePath, protectedPath);
      files[protectedPath] = parseAccessRule(rawRule, `vaults.${vaultId}.files.${protectedPath}`);
    }
    vaults[vaultId] = {
      repository: string(vault.repository, `vaults.${vaultId}.repository`),
      files,
    };
  }
  const rawDevelopmentUsers = root.developmentUsers ?? [];
  if (!Array.isArray(rawDevelopmentUsers)) {
    throw new Error("developmentUsers must be an array");
  }
  const developmentUsers: DevelopmentUser[] = rawDevelopmentUsers.map((rawUser, index) => {
    const user = object(rawUser, `developmentUsers[${index}]`);
    return {
      id: positiveInteger(user.id, `developmentUsers[${index}].id`),
      login: string(user.login, `developmentUsers[${index}].login`),
    };
  });
  const githubClientId = root.githubClientId;
  if (githubClientId !== undefined && typeof githubClientId !== "string") {
    throw new Error("githubClientId must be a string");
  }
  const sessionMinutes = positiveInteger(root.sessionMinutes ?? 60, "sessionMinutes");
  if (sessionMinutes > MAX_SESSION_MINUTES) {
    throw new Error(`sessionMinutes must not exceed ${MAX_SESSION_MINUTES}`);
  }
  return {
    version: 1,
    ...(githubClientId === undefined ? {} : { githubClientId }),
    sessionMinutes,
    keyId: string(root.keyId, "keyId"),
    developmentUsers,
    vaults,
  };
}
