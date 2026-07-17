import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { once } from "node:events";
import test from "node:test";

import { AuthClient } from "../src/auth-client.js";
import { createAuthServer } from "../src/auth-server.js";
import { decryptFile, encryptFile } from "../src/crypto.js";
import { decodeBase64Url } from "../src/encoding.js";
import type { ServerPolicy } from "../src/types.js";

const policy: ServerPolicy = {
  version: 1,
  sessionMinutes: 60,
  keyId: "test-key",
  developmentUsers: [
    { id: 101, login: "allowed" },
    { id: 202, login: "denied" },
  ],
  vaults: {
    "vault-1": {
      repository: "acme/project",
      files: {
        ".env": { users: [101], teams: [] },
      },
    },
  },
};

test("authorization service issues and unwraps keys for an authorized session", async (context) => {
  const server = createAuthServer({
    policy,
    keyEncryptionKey: randomBytes(32),
    allowDevelopmentAuth: true,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const port = (server.address() as AddressInfo).port;
  const client = new AuthClient(`http://127.0.0.1:${port}`);
  const session = await client.developmentLogin(101);

  const generated = await client.dataKey(session, "vault-1", ".env");
  assert.ok(generated.wrappedKey);
  const key = decodeBase64Url(generated.key, 32);
  const encrypted = encryptFile(
    Buffer.from("SECRET=value\n"),
    key,
    generated.wrappedKey,
    "vault-1",
    ".env",
  );
  const unwrapped = await client.unwrap(session, "vault-1", ".env", generated.wrappedKey);
  const plaintext = decryptFile(
    encrypted,
    decodeBase64Url(unwrapped.key, 32),
    "vault-1",
    ".env",
  );
  assert.equal(plaintext.toString("utf8"), "SECRET=value\n");
});

test("authorization service rejects a user outside the file policy", async (context) => {
  const server = createAuthServer({
    policy,
    keyEncryptionKey: randomBytes(32),
    allowDevelopmentAuth: true,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  const port = (server.address() as AddressInfo).port;
  const client = new AuthClient(`http://127.0.0.1:${port}`);
  const session = await client.developmentLogin(202);

  await assert.rejects(() => client.dataKey(session, "vault-1", ".env"), /not authorized/);
});
