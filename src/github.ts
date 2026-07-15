interface GitHubDeviceCode {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

interface GitHubTokenResponse {
  access_token?: string;
  error?: string;
  interval?: number;
}

export interface GitHubIdentity {
  id: number;
  login: string;
}

interface GitHubInstallation {
  id: number;
}

interface GitHubInstallationToken {
  token: string;
  expires_at: string;
}

async function githubRequest<T>(url: string, init: RequestInit): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  headers.set("user-agent", "rolegit/0.1");
  if (url.startsWith("https://api.github.com/")) {
    headers.set("x-github-api-version", "2022-11-28");
  }
  const response = await fetch(url, {
    ...init,
    headers,
    signal: AbortSignal.timeout(20_000),
  });
  const body = (await response.json().catch(() => ({}))) as T;
  if (!response.ok) throw new Error(`GitHub returned ${response.status}`);
  return body;
}

export function startGitHubDeviceFlow(clientId: string): Promise<GitHubDeviceCode> {
  return githubRequest("https://github.com/login/device/code", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, scope: "read:org" }),
  });
}

export function pollGitHubDeviceFlow(clientId: string, deviceCode: string): Promise<GitHubTokenResponse> {
  return githubRequest("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      device_code: deviceCode,
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    }),
  });
}

export function getGitHubIdentity(token: string): Promise<GitHubIdentity> {
  return githubRequest("https://api.github.com/user", {
    headers: { authorization: `Bearer ${token}` },
  });
}

export async function isActiveTeamMember(
  token: string,
  organization: string,
  slug: string,
  login: string,
): Promise<boolean> {
  const url = `https://api.github.com/orgs/${encodeURIComponent(organization)}/teams/${encodeURIComponent(slug)}/memberships/${encodeURIComponent(login)}`;
  try {
    const membership = await githubRequest<{ state?: string }>(url, {
      headers: { authorization: `Bearer ${token}` },
    });
    return membership.state === "active";
  } catch (error) {
    if ((error as Error).message === "GitHub returned 404") return false;
    throw error;
  }
}

export function createGitHubAppJwt(
  privateKey: KeyObject,
  clientId: string = OFFICIAL_GITHUB_APP.clientId,
  now = Math.floor(Date.now() / 1000),
): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const input = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({
    iat: now - 60,
    exp: now + 9 * 60,
    iss: clientId,
  })}`;
  const signature = sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url");
  return `${input}.${signature}`;
}

function parseRepository(repository: string): { apiPath: string; name: string } {
  const match = /^([^/]+)\/([^/]+)$/.exec(repository);
  if (!match) throw new Error(`invalid GitHub repository name: ${repository}`);
  return {
    apiPath: `${encodeURIComponent(match[1]!)}\/${encodeURIComponent(match[2]!)}`,
    name: match[2]!,
  };
}

export class GitHubAppClient {
  private readonly privateKey: KeyObject;
  private readonly tokens = new Map<string, { token: string; expiresAt: number }>();

  constructor(
    privateKeyPem: string | Buffer,
    private readonly clientId: string = OFFICIAL_GITHUB_APP.clientId,
  ) {
    this.privateKey = createPrivateKey(privateKeyPem);
  }

  async installationToken(repository: string): Promise<string> {
    const cached = this.tokens.get(repository);
    if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;

    const jwt = createGitHubAppJwt(this.privateKey, this.clientId);
    const parsedRepository = parseRepository(repository);
    const installation = await githubRequest<GitHubInstallation>(
      `https://api.github.com/repos/${parsedRepository.apiPath}/installation`,
      { headers: { authorization: `Bearer ${jwt}` } },
    );
    const result = await githubRequest<GitHubInstallationToken>(
      `https://api.github.com/app/installations/${installation.id}/access_tokens`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${jwt}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ repositories: [parsedRepository.name] }),
      },
    );
    const expiresAt = new Date(result.expires_at).getTime();
    if (!result.token || !Number.isFinite(expiresAt)) {
      throw new Error("GitHub returned an invalid installation token");
    }
    this.tokens.set(repository, { token: result.token, expiresAt });
    return result.token;
  }
}
import { createPrivateKey, sign, type KeyObject } from "node:crypto";

import { OFFICIAL_GITHUB_APP } from "./app.js";
