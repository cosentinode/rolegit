export function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

export function decodeBase64Url(value: unknown, expectedLength?: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("invalid base64url value");
  }

  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new Error("non-canonical base64url value");
  }
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} decoded bytes, received ${decoded.length}`);
  }
  return decoded;
}
