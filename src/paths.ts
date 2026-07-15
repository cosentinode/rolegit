import path from "node:path";

export function normalizeProtectedPath(value: string): string {
  if (value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error("protected path contains unsupported characters");
  }
  const slashPath = value.replaceAll("\\", "/");
  const normalized = path.posix.normalize(slashPath);
  if (
    normalized === "." ||
    path.posix.isAbsolute(normalized) ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    /^[A-Za-z]:\//.test(normalized)
  ) {
    throw new Error(`protected path must stay inside the repository: ${value}`);
  }
  return normalized;
}
