import path from "node:path";

const WINDOWS_DEVICE_NAME = /^(con|prn|aux|nul|clock\$|conin\$|conout\$|com(?:[0-9]|\u00b9|\u00b2|\u00b3)|lpt(?:[0-9]|\u00b9|\u00b2|\u00b3))$/i;

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
    if (WINDOWS_DEVICE_NAME.test(deviceName)) {
      throw new Error(`protected path uses a reserved Windows name: ${value}`);
    }
  }
  return normalized;
}

export function normalizePlaintextPath(value: string): string {
  const normalized = normalizeProtectedPath(value);
  const portablePath = normalized.toLowerCase();
  if ([".enclist", ".rolegit", ".git"].some((metadataPath) =>
    portablePath === metadataPath || portablePath.startsWith(`${metadataPath}/`))) {
    throw new Error(`repository metadata cannot be protected: ${value}`);
  }
  return normalized;
}
