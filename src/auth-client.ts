import type { LocalSession, WrappedKey } from "./types.js";

interface DeviceStart {
  requestId: string;
  userCode: string;
  verificationUri: string;
  interval: number;
  expiresAt: string;
}

interface DevicePollPending {
  status: "pending";
  interval: number;
}

interface DevicePollComplete {
  status: "complete";
  session: Omit<LocalSession, "server">;
}

interface KeyResponse {
  key: string;
  wrappedKey?: WrappedKey;
}

export class AuthClient {
  constructor(private readonly server: string) {}

  private async request<T>(route: string, init: RequestInit = {}, token?: string): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("content-type", "application/json");
    if (token) headers.set("authorization", `Bearer ${token}`);
    let response: Response;
    try {
      response = await fetch(new URL(route, this.server), {
        ...init,
        headers,
        signal: AbortSignal.timeout(30_000),
      });
    } catch (error) {
      throw new Error(`authorization service unavailable: ${(error as Error).message}`);
    }
    const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) {
      throw new Error(typeof body.error === "string" ? body.error : `authorization failed (${response.status})`);
    }
    return body as T;
  }

  startDeviceLogin(): Promise<DeviceStart> {
    return this.request("/v1/auth/device/start", { method: "POST", body: "{}" });
  }

  pollDeviceLogin(requestId: string): Promise<DevicePollPending | DevicePollComplete> {
    return this.request("/v1/auth/device/poll", {
      method: "POST",
      body: JSON.stringify({ requestId }),
    });
  }

  async developmentLogin(userId: number): Promise<LocalSession> {
    const result = await this.request<{ session: Omit<LocalSession, "server"> }>(
      "/v1/auth/development",
      { method: "POST", body: JSON.stringify({ userId }) },
    );
    return { server: this.server, ...result.session };
  }

  async dataKey(session: LocalSession, vaultId: string, path: string): Promise<KeyResponse> {
    return this.request(
      "/v1/keys/generate",
      { method: "POST", body: JSON.stringify({ vaultId, path }) },
      session.token,
    );
  }

  async unwrap(
    session: LocalSession,
    vaultId: string,
    path: string,
    wrappedKey: WrappedKey,
  ): Promise<KeyResponse> {
    return this.request(
      "/v1/keys/unwrap",
      { method: "POST", body: JSON.stringify({ vaultId, path, wrappedKey }) },
      session.token,
    );
  }

  async logout(session: LocalSession): Promise<void> {
    await this.request("/v1/auth/logout", { method: "POST", body: "{}" }, session.token);
  }
}
