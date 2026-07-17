import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";

import {
  decryptFile,
  encryptFile,
  generateDataKey,
  parseEncryptedFile,
  unwrapDataKey,
  wrapDataKey,
} from "../src/crypto.js";

test("envelope encryption round trips binary data", () => {
  const kek = randomBytes(32);
  const dataKey = generateDataKey();
  const plaintext = Buffer.from([0, 1, 2, 255, 42]);
  const wrapped = wrapDataKey(dataKey, kek, "test-key", "vault-1", ".env");
  const encrypted = encryptFile(plaintext, dataKey, wrapped, "vault-1", ".env");

  const unwrapped = unwrapDataKey(encrypted.wrappedKey, kek, "vault-1", ".env");
  assert.deepEqual(decryptFile(encrypted, unwrapped, "vault-1", ".env"), plaintext);
});

test("encrypting identical plaintext produces different envelopes", () => {
  const kek = randomBytes(32);
  const plaintext = Buffer.from("SECRET=value\n");
  const firstKey = generateDataKey();
  const secondKey = generateDataKey();
  const first = encryptFile(
    plaintext,
    firstKey,
    wrapDataKey(firstKey, kek, "test-key", "vault-1", ".env"),
    "vault-1",
    ".env",
  );
  const second = encryptFile(
    plaintext,
    secondKey,
    wrapDataKey(secondKey, kek, "test-key", "vault-1", ".env"),
    "vault-1",
    ".env",
  );

  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.notEqual(first.wrappedKey.ciphertext, second.wrappedKey.ciphertext);
});

test("tampering and path swapping fail authentication", () => {
  const kek = randomBytes(32);
  const dataKey = generateDataKey();
  const encrypted = encryptFile(
    Buffer.from("SECRET=value\n"),
    dataKey,
    wrapDataKey(dataKey, kek, "test-key", "vault-1", ".env"),
    "vault-1",
    ".env",
  );
  const tampered = structuredClone(encrypted);
  tampered.tag = `${tampered.tag[0] === "A" ? "B" : "A"}${tampered.tag.slice(1)}`;

  assert.throws(() => decryptFile(tampered, dataKey, "vault-1", ".env"));
  assert.throws(() => decryptFile(encrypted, dataKey, "vault-1", ".env.production"));
  assert.throws(() => unwrapDataKey(encrypted.wrappedKey, kek, "vault-1", ".env.production"));
});

test("encrypted file parser rejects malformed fields", () => {
  assert.throws(
    () => parseEncryptedFile({ version: 1, cipher: "aes-256-gcm", nonce: "bad!" }),
    /wrappedKey/,
  );
});
