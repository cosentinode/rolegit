import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

import { decodeBase64Url, encodeBase64Url } from "./encoding.js";
import type { EncryptedFile, WrappedKey } from "./types.js";

const CIPHER = "aes-256-gcm";
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function dataAad(vaultId: string, path: string): Buffer {
  return Buffer.from(`rolegit:v1\0data\0${vaultId}\0${path}\0${CIPHER}`, "utf8");
}

function keyAad(vaultId: string, path: string, kid: string): Buffer {
  return Buffer.from(`rolegit:v1\0key\0${vaultId}\0${path}\0${kid}`, "utf8");
}

function encryptAesGcm(plaintext: Buffer, key: Buffer, aad: Buffer) {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(CIPHER, key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    nonce: encodeBase64Url(nonce),
    ciphertext: encodeBase64Url(ciphertext),
    tag: encodeBase64Url(cipher.getAuthTag()),
  };
}

function decryptAesGcm(
  encrypted: { nonce: string; ciphertext: string; tag: string },
  key: Buffer,
  aad: Buffer,
): Buffer {
  const nonce = decodeBase64Url(encrypted.nonce, NONCE_BYTES);
  const ciphertext = decodeBase64Url(encrypted.ciphertext);
  const tag = decodeBase64Url(encrypted.tag, TAG_BYTES);
  const decipher = createDecipheriv(CIPHER, key, nonce, { authTagLength: TAG_BYTES });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function generateDataKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") throw new Error(`encrypted file ${key} must be a string`);
  return value;
}

export function parseEncryptedFile(value: unknown): EncryptedFile {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("encrypted file must be an object");
  }
  const record = value as Record<string, unknown>;
  if (record.version !== 1 || record.cipher !== CIPHER) {
    throw new Error("unsupported encrypted file format");
  }
  if (typeof record.wrappedKey !== "object" || record.wrappedKey === null) {
    throw new Error("encrypted file wrappedKey must be an object");
  }
  const wrapped = record.wrappedKey as Record<string, unknown>;
  const encrypted: EncryptedFile = {
    version: 1,
    cipher: CIPHER,
    nonce: requiredString(record, "nonce"),
    ciphertext: requiredString(record, "ciphertext"),
    tag: requiredString(record, "tag"),
    wrappedKey: {
      kid: requiredString(wrapped, "kid"),
      nonce: requiredString(wrapped, "nonce"),
      ciphertext: requiredString(wrapped, "ciphertext"),
      tag: requiredString(wrapped, "tag"),
    },
  };
  decodeBase64Url(encrypted.nonce, NONCE_BYTES);
  decodeBase64Url(encrypted.ciphertext);
  decodeBase64Url(encrypted.tag, TAG_BYTES);
  decodeBase64Url(encrypted.wrappedKey.nonce, NONCE_BYTES);
  decodeBase64Url(encrypted.wrappedKey.ciphertext, KEY_BYTES);
  decodeBase64Url(encrypted.wrappedKey.tag, TAG_BYTES);
  return encrypted;
}

export function validateWrappedKey(value: WrappedKey): WrappedKey {
  if (typeof value !== "object" || value === null) throw new Error("wrapped key must be an object");
  const record = value as unknown as Record<string, unknown>;
  const wrapped = {
    kid: requiredString(record, "kid"),
    nonce: requiredString(record, "nonce"),
    ciphertext: requiredString(record, "ciphertext"),
    tag: requiredString(record, "tag"),
  };
  decodeBase64Url(wrapped.nonce, NONCE_BYTES);
  decodeBase64Url(wrapped.ciphertext, KEY_BYTES);
  decodeBase64Url(wrapped.tag, TAG_BYTES);
  return wrapped;
}

export function encryptFile(
  plaintext: Buffer,
  dataKey: Buffer,
  wrappedKey: WrappedKey,
  vaultId: string,
  path: string,
): EncryptedFile {
  if (dataKey.length !== KEY_BYTES) {
    throw new Error("data key must be 32 bytes");
  }
  return {
    version: 1,
    cipher: CIPHER,
    ...encryptAesGcm(plaintext, dataKey, dataAad(vaultId, path)),
    wrappedKey: validateWrappedKey(wrappedKey),
  };
}

export function decryptFile(
  encrypted: EncryptedFile,
  dataKey: Buffer,
  vaultId: string,
  path: string,
): Buffer {
  if (encrypted.version !== 1 || encrypted.cipher !== CIPHER) {
    throw new Error("unsupported encrypted file format");
  }
  if (dataKey.length !== KEY_BYTES) {
    throw new Error("data key must be 32 bytes");
  }
  return decryptAesGcm(encrypted, dataKey, dataAad(vaultId, path));
}

export function wrapDataKey(
  dataKey: Buffer,
  keyEncryptionKey: Buffer,
  kid: string,
  vaultId: string,
  path: string,
): WrappedKey {
  if (dataKey.length !== KEY_BYTES || keyEncryptionKey.length !== KEY_BYTES) {
    throw new Error("data and key-encryption keys must be 32 bytes");
  }
  return {
    kid,
    ...encryptAesGcm(dataKey, keyEncryptionKey, keyAad(vaultId, path, kid)),
  };
}

export function unwrapDataKey(
  wrapped: WrappedKey,
  keyEncryptionKey: Buffer,
  vaultId: string,
  path: string,
): Buffer {
  if (keyEncryptionKey.length !== KEY_BYTES) {
    throw new Error("key-encryption key must be 32 bytes");
  }
  const validated = validateWrappedKey(wrapped);
  return decryptAesGcm(validated, keyEncryptionKey, keyAad(vaultId, path, validated.kid));
}
