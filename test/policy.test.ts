import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_SESSION_MINUTES,
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

test("rejects non-portable Windows paths and case aliases", () => {
  for (const unsafe of [
    "NUL",
    "con.txt",
    "CONIN$",
    "conout$.txt",
    "CLOCK$",
    "COM0.log",
    "COM\u00b9",
    "com\u00b2.env",
    "LPT\u00b3.log",
    "lpt0",
    "secrets. ",
    "secrets.",
    "secrets:stream",
    "a?.env",
  ]) {
    assert.throws(() => normalizeProtectedPath(unsafe), /Windows/);
  }
  const files = {
    "Config.env": { object: encryptedObjectPath("Config.env") },
    "config.env": { object: encryptedObjectPath("config.env") },
  };
  assert.throws(() => parseEnclist({
    version: 1,
    vaultId: "vault",
    authServer: "http://127.0.0.1:8787",
    files,
  }), /differ only by case/);
  assert.throws(() => parseServerPolicy({
    version: 1,
    sessionMinutes: 60,
    keyId: "dev",
    vaults: {
      vault: {
        repository: "acme/project",
        files: {
          "Config.env": { users: [1], teams: [] },
          "config.env": { users: [1], teams: [] },
        },
      },
    },
  }), /differ only by case/);
  assert.throws(() => normalizeProtectedPath("Stra\u00DFe.env"), /multi-character Unicode case mapping/);
  assert.throws(() => normalizeProtectedPath("e\u0301.env"), /NFC Unicode normalization/);
});

test("policies reject Unicode Windows case equivalents", () => {
  const capitalSigma = "\u03A3.env";
  const finalSigma = "\u03C2.env";
  assert.throws(() => parseEnclist({
    version: 1,
    vaultId: "vault",
    authServer: "http://127.0.0.1:8787",
    files: {
      [capitalSigma]: { object: encryptedObjectPath(capitalSigma) },
      [finalSigma]: { object: encryptedObjectPath(finalSigma) },
    },
  }), /differ only by case/);
  assert.throws(() => parseServerPolicy({
    version: 1,
    sessionMinutes: 60,
    keyId: "dev",
    vaults: {
      vault: {
        repository: "acme/project",
        files: {
          [capitalSigma]: { users: [101], teams: [] },
          [finalSigma]: { users: [202], teams: [] },
        },
      },
    },
  }), /differ only by case/);
});

test("encrypted object paths are deterministic and opaque", () => {
  const objectPath = encryptedObjectPath(".env.production");
  assert.match(objectPath, /^\.rolegit\/vault\/[a-f0-9]{64}\.json$/);
  assert.equal(objectPath, encryptedObjectPath(".env.production"));
});

test("enclist rejects encrypted object aliases", () => {
  const sharedObject = encryptedObjectPath("a.env");
  assert.throws(
    () => parseEnclist({
      version: 1,
      vaultId: "vault",
      authServer: "http://127.0.0.1:8787",
      files: {
        "a.env": { object: sharedObject },
        "b.env": { object: sharedObject },
      },
    }),
    /canonical vault path/,
  );
});

test("policies reject portable metadata namespaces", () => {
  for (const protectedPath of [".ENCLIST", ".GITIGNORE", ".gitignore/child", ".rolegit", ".ROLEGIT/file", ".git/config"]) {
    assert.throws(() => parseEnclist({
      version: 1,
      vaultId: "vault",
      authServer: "http://127.0.0.1:8787",
      files: { [protectedPath]: { object: encryptedObjectPath(protectedPath) } },
    }), /metadata cannot be protected/);
  }
  assert.throws(() => parseServerPolicy({
    version: 1,
    sessionMinutes: 60,
    keyId: "dev",
    vaults: {
      vault: {
        repository: "acme/project",
        files: { ".GIT/config": { users: [1], teams: [] } },
      },
    },
  }), /metadata cannot be protected/);
});

test("policy maps preserve prototype-named files and vaults", () => {
  const clientFiles = {
    ["__proto__"]: { object: encryptedObjectPath("__proto__") },
    constructor: { object: encryptedObjectPath("constructor") },
  };
  const clientPolicy = parseEnclist({
    version: 1,
    vaultId: "vault",
    authServer: "http://127.0.0.1:8787",
    files: clientFiles,
  });
  assert.equal(Object.hasOwn(clientPolicy.files, "__proto__"), true);
  assert.equal(Object.hasOwn(clientPolicy.files, "constructor"), true);

  const serverPolicy = parseServerPolicy({
    version: 1,
    sessionMinutes: 60,
    keyId: "dev",
    vaults: {
      ["__proto__"]: {
        repository: "acme/project",
        files: {
          ["__proto__"]: { users: [1], teams: [] },
          constructor: { users: [1], teams: [] },
        },
      },
    },
  });
  assert.equal(Object.hasOwn(serverPolicy.vaults, "__proto__"), true);
  assert.equal(Object.hasOwn(serverPolicy.vaults.__proto__!.files, "__proto__"), true);
  assert.equal(Object.hasOwn(serverPolicy.vaults.__proto__!.files, "constructor"), true);
});

test("server policies reject duplicate normalized protected paths", () => {
  const rule = (user: number) => ({ users: [user], teams: [] });
  for (const files of [
    { "dir/../secret.env": rule(101), "secret.env": rule(202) },
    { ["nested\\..\\__proto__"]: rule(101), ["__proto__"]: rule(202) },
    { ["nested/../constructor"]: rule(101), constructor: rule(202) },
  ]) {
    assert.throws(() => parseServerPolicy({
      version: 1,
      sessionMinutes: 60,
      keyId: "dev",
      vaults: {
        ["__proto__"]: {
          repository: "acme/project",
          files,
        },
      },
    }), /duplicate protected path/);
  }
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

test("server policy caps representable session durations", () => {
  assert.throws(
    () => parseServerPolicy({
      version: 1,
      sessionMinutes: MAX_SESSION_MINUTES + 1,
      keyId: "dev",
      vaults: {},
    }),
    /must not exceed/,
  );
});
