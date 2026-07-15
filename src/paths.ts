import path from "node:path";

export function normalizeProtectedPath(value: string): string {
  if (/[\x00-\x1f]/.test(value)) {
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
  for (const component of normalized.split("/")) {
    if (/[<>:"|?*]/.test(component) || /[ .]$/.test(component)) {
      throw new Error(`protected path is not portable to Windows: ${value}`);
    }
    const deviceName = component.split(".", 1)[0]!;
    if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(deviceName)) {
      throw new Error(`protected path uses a reserved Windows name: ${value}`);
    }
  }
  return normalized;
}
