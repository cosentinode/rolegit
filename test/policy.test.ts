import assert from "node:assert/strict";
import test from "node:test";

import {
  encryptedObjectPath,
  normalizeProtectedPath,
  parseEnclist,
  parseServerPolicy,
} from "../src/policy.js";

test("normalizes repository-relative protected paths", () => {
  assert.equal(normalizeProtectedPath("config\\production.env"), "config/production.env");
  assert.throws(() => normalizeProtectedPath("../outside"), /inside the repository/);
  assert.throws(() => normalizeProtectedPath("/absolute"), /inside the repository/);
});

test("encrypted object paths are deterministic and opaque", () => {
  const objectPath = encryptedObjectPath(".env.production");
  assert.match(objectPath, /^\.rolegit\/vault\/[a-f0-9]{64}\.json$/);
  assert.equal(objectPath, encryptedObjectPath(".env.production"));
});

test("enclist only permits loopback HTTP", () => {
  const base = { version: 1, vaultId: "vault", files: {} };
  assert.doesNotThrow(() => parseEnclist({ ...base, authServer: "http://127.0.0.1:8787" }));
  assert.doesNotThrow(() => parseEnclist({ ...base, authServer: "http://[::1]:8787" }));
  assert.throws(
    () => parseEnclist({ ...base, authServer: "http://example.com" }),
    /must use HTTPS/,
  );
});

test("server policy requires explicit non-empty access rules", () => {
  assert.throws(
    () =>
      parseServerPolicy({
        version: 1,
        sessionMinutes: 60,
        keyId: "dev",
        vaults: {
          vault: {
            repository: "acme/project",
            files: { ".env": { users: [], teams: [] } },
          },
        },
      }),
    /authorize at least one/,
  );
});
