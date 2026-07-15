import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { OFFICIAL_GITHUB_APP } from "./app.js";
import { generateDataKey, unwrapDataKey, wrapDataKey } from "./crypto.js";
import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import {
  getGitHubIdentity,
  isActiveTeamMember,
  pollGitHubDeviceFlow,
  startGitHubDeviceFlow,
  type GitHubAppClient,
  type GitHubIdentity,
} from "./github.js";
import { normalizeProtectedPath } from "./policy.js";
import type { ServerPolicy, WrappedKey } from "./types.js";

interface ActiveSession {
  tokenHash: Buffer;
  expiresAt: number;
  user: GitHubIdentity;
  githubToken?: string;
}

interface DeviceAttempt {
  deviceCode: string;
  expiresAt: number;
  nextPollAt: number;
  interval: number;
}

interface AuthServerOptions {
  policy: ServerPolicy;
  keyEncryptionKey: Buffer;
  allowDevelopmentAuth: boolean;
  githubApp?: GitHubAppClient;
}

const MAX_BODY_BYTES = 64 * 1024;

function tokenHash(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(buffer);
  }
  if (chunks.length === 0) return {};
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("request body must be an object");
  }
  return parsed as Record<string, unknown>;
}

function send(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  response.end(body);
}

export function createAuthServer(options: AuthServerOptions) {
  if (options.keyEncryptionKey.length !== 32) throw new Error("ROLEGIT_KEK must decode to 32 bytes");
  const sessions = new Map<string, ActiveSession>();
  const deviceAttempts = new Map<string, DeviceAttempt>();
  const githubClientId = options.policy.githubClientId ?? OFFICIAL_GITHUB_APP.clientId;
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (session.expiresAt <= now) {
        session.tokenHash.fill(0);
        sessions.delete(id);
      }
    }
    for (const [id, attempt] of deviceAttempts) {
      if (attempt.expiresAt <= now) deviceAttempts.delete(id);
    }
  }, 60_000);
  cleanup.unref();

  function issueSession(user: GitHubIdentity, githubToken?: string) {
    const token = encodeBase64Url(randomBytes(32));
    const expiresAt = Date.now() + options.policy.sessionMinutes * 60_000;
    const active: ActiveSession = {
      tokenHash: tokenHash(token),
      expiresAt,
      user,
      ...(githubToken === undefined ? {} : { githubToken }),
    };
    sessions.set(token.slice(0, 12), active);
    return {
      token,
      expiresAt: new Date(expiresAt).toISOString(),
      user,
    };
  }

  function authenticate(request: IncomingMessage): ActiveSession {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) throw new Error("missing session token");
    const token = authorization.slice(7);
    const session = sessions.get(token.slice(0, 12));
    if (!session || !timingSafeEqual(session.tokenHash, tokenHash(token))) {
      throw new Error("invalid session token");
    }
    if (session.expiresAt <= Date.now()) {
      sessions.delete(token.slice(0, 12));
      throw new Error("session expired");
    }
    return session;
  }

  async function authorize(session: ActiveSession, vaultId: string, protectedPath: string): Promise<void> {
    const vault = options.policy.vaults[vaultId];
    const rule = vault?.files[protectedPath];
    if (!rule) throw new Error("file is not registered with the authorization service");
    if (rule.users.includes(session.user.id)) return;
    const membershipToken = options.githubApp && vault
      ? await options.githubApp.installationToken(vault.repository)
      : session.githubToken;
    if (!membershipToken) throw new Error("user is not authorized for this file");
    for (const team of rule.teams) {
      if (
        await isActiveTeamMember(
          membershipToken,
          team.organization,
          team.slug,
          session.user.login,
        )
      ) return;
    }
    throw new Error("user is not authorized for this file");
  }

  const server = createServer(async (request, response) => {
    try {
      if (request.method !== "POST") {
        send(response, 405, { error: "method not allowed" });
        return;
      }
      const url = new URL(request.url ?? "/", "http://localhost");
      const body = await readJson(request);

      if (url.pathname === "/v1/auth/device/start") {
        const github = await startGitHubDeviceFlow(githubClientId);
        const requestId = encodeBase64Url(randomBytes(24));
        const interval = Math.max(5, github.interval);
        const expiresAt = Date.now() + github.expires_in * 1000;
        deviceAttempts.set(requestId, {
          deviceCode: github.device_code,
          expiresAt,
          nextPollAt: Date.now() + interval * 1000,
          interval,
        });
        send(response, 200, {
          requestId,
          userCode: github.user_code,
          verificationUri: github.verification_uri,
          interval,
          expiresAt: new Date(expiresAt).toISOString(),
        });
        return;
      }

      if (url.pathname === "/v1/auth/device/poll") {
        if (typeof body.requestId !== "string") {
          throw new Error("invalid device login request");
        }
        const attempt = deviceAttempts.get(body.requestId);
        if (!attempt || attempt.expiresAt <= Date.now()) throw new Error("device login expired");
        if (attempt.nextPollAt > Date.now()) {
          send(response, 200, { status: "pending", interval: attempt.interval });
          return;
        }
        attempt.nextPollAt = Date.now() + attempt.interval * 1000;
        const result = await pollGitHubDeviceFlow(githubClientId, attempt.deviceCode);
        if (result.error === "authorization_pending") {
          send(response, 200, { status: "pending", interval: attempt.interval });
          return;
        }
        if (result.error === "slow_down") {
          attempt.interval += 5;
          attempt.nextPollAt = Date.now() + attempt.interval * 1000;
          send(response, 200, { status: "pending", interval: attempt.interval });
          return;
        }
        if (!result.access_token) throw new Error(result.error ?? "GitHub device login failed");
        const user = await getGitHubIdentity(result.access_token);
        deviceAttempts.delete(body.requestId);
        send(response, 200, { status: "complete", session: issueSession(user, result.access_token) });
        return;
      }

      if (url.pathname === "/v1/auth/development") {
        if (!options.allowDevelopmentAuth || !Number.isSafeInteger(body.userId)) {
          throw new Error("development authentication is disabled");
        }
        const user = options.policy.developmentUsers.find((candidate) => candidate.id === body.userId);
        if (!user) throw new Error("unknown development user");
        send(response, 200, { session: issueSession(user) });
        return;
      }

      if (url.pathname === "/v1/auth/logout") {
        const authorization = request.headers.authorization;
        const session = authenticate(request);
        if (authorization) sessions.delete(authorization.slice(7, 19));
        session.tokenHash.fill(0);
        send(response, 200, {});
        return;
      }

      if (url.pathname === "/v1/keys/generate") {
        const session = authenticate(request);
        if (typeof body.vaultId !== "string" || typeof body.path !== "string") {
          throw new Error("vaultId and path are required");
        }
        const protectedPath = normalizeProtectedPath(body.path);
        await authorize(session, body.vaultId, protectedPath);
        const key = generateDataKey();
        const wrappedKey = wrapDataKey(
          key,
          options.keyEncryptionKey,
          options.policy.keyId,
          body.vaultId,
          protectedPath,
        );
        send(response, 200, { key: encodeBase64Url(key), wrappedKey });
        key.fill(0);
        return;
      }

      if (url.pathname === "/v1/keys/unwrap") {
        const session = authenticate(request);
        if (
          typeof body.vaultId !== "string" ||
          typeof body.path !== "string" ||
          typeof body.wrappedKey !== "object" ||
          body.wrappedKey === null
        ) throw new Error("vaultId, path, and wrappedKey are required");
        const protectedPath = normalizeProtectedPath(body.path);
        await authorize(session, body.vaultId, protectedPath);
        const wrappedKey = body.wrappedKey as unknown as WrappedKey;
        if (wrappedKey.kid !== options.policy.keyId) throw new Error("unknown key-encryption key");
        const key = unwrapDataKey(
          wrappedKey,
          options.keyEncryptionKey,
          body.vaultId,
          protectedPath,
        );
        send(response, 200, { key: encodeBase64Url(key) });
        key.fill(0);
        return;
      }

      send(response, 404, { error: "not found" });
    } catch (error) {
      send(response, 400, { error: (error as Error).message });
    }
  });
  server.on("close", () => clearInterval(cleanup));
  return server;
}

export function decodeKeyEncryptionKey(value: string): Buffer {
  return decodeBase64Url(value, 32);
}
