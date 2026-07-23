import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("public docs preserve architecture, release, and parsing boundaries", async () => {
  const [readme, security, architecture, protocols] = await Promise.all([
    readFile(path.join(projectRoot, "README.md"), "utf8"),
    readFile(path.join(projectRoot, "docs/security.md"), "utf8"),
    readFile(path.join(projectRoot, "docs/adr/0001-product-modes-and-trust-boundaries.md"), "utf8"),
    readFile(path.join(projectRoot, "docs/adr/0002-branches-protocols-and-repository-ownership.md"), "utf8"),
  ]);
  assert.match(readme, /Git\/customer synchronization path remains trusted for signed-state freshness/);
  assert.match(readme, /does not revoke older\s+ciphertext and wrapped keys retained in Git history/);
  assert.match(readme, /encrypted-object, `\.enclist`, and server-policy readers/);
  assert.match(readme, /repository writer or Git split view\s+can replace it/);
  assert.match(readme, /does not pin the\s+endpoint to the intended customer service identity/);
  assert.match(readme, /`develop` is the integration branch and the base for feature and maintenance pull requests/);
  assert.match(readme, /`main`\s+contains stable release history and is the base for reviewed release-promotion pull requests/);
  assert.match(security, /stale or split view can delay revocation for future seals/);
  assert.match(security, /persisted wrapped DEKs and DEKs already\s+released to clients do not acquire that session expiry/);
  assert.match(security, /legitimate service policy controls only requests that\s+reach it and is not the sole authority for future seals/);
  assert.match(architecture, /inside Community's authorization-freshness\s+boundary/);
  assert.match(architecture, /removed recipient who retains that private key can later\s+check out and decrypt an older commit/);
  assert.match(architecture, /Credentials, sessions, or tokens expire independently/);
  assert.match(architecture, /legitimate server policy is therefore not the sole authority for future seals/);
  assert.match(architecture, /endpoint replacement alone does not reveal objects\s+previously sealed through the expected service/);
  const diagrams = architecture.match(/```mermaid\r?\n[\s\S]*?\r?\n```/g) ?? [];
  assert.equal(diagrams.length, 6);
  for (const diagram of diagrams) {
    assert.match(diagram, /\|seal:/);
    assert.match(diagram, /\|unlock:/);
    assert.match(diagram, /plaintext-DEK holder/);
  }
  const keyProviderDiagram = diagrams.find((diagram) => diagram.includes("Customer key provider and agent"));
  assert.ok(keyProviderDiagram);
  assert.match(keyProviderDiagram, /seal A: request provider-generated DEK/);
  assert.match(keyProviderDiagram, /seal A: return plaintext DEK and wrapped DEK/);
  assert.match(keyProviderDiagram, /seal B1: send client-generated plaintext DEK and context for remote wrap/);
  assert.match(keyProviderDiagram, /seal B1: return wrapped DEK only/);
  assert.match(keyProviderDiagram, /seal B2: authenticated public wrapping key for local wrap; no plaintext DEK received/);
  assert.match(keyProviderDiagram, /unlock: return plaintext DEK after authorization/);
  assert.match(architecture, /provider contract requires wrap and unwrap without assuming a\s+provider-specific data-key-generation API/);
  assert.match(architecture, /Provider-generated and remote-wrap\s+sealing place plaintext DEKs inside the provider\/agent boundary/);
  assert.match(architecture, /local public-key wrapping does not do\s+so during sealing/);
  assert.match(protocols, /silently ignore unknown object fields/);
  assert.match(protocols, /not fail-closed extensibility/);
  assert.match(protocols, /`develop` is the integration branch and the base for feature and maintenance pull requests/);
  assert.match(protocols, /`main` contains stable release history and is the base for reviewed release-promotion pull requests/);
});

test("package rebuild excludes stale output and includes required files", async (context) => {
  const cleanRoot = await mkdtemp(path.join(tmpdir(), "rolegit-package-"));
  context.after(() => rm(cleanRoot, { recursive: true, force: true }));
  for (const entry of [
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "README.md",
    "LICENSE",
    "server-policy.example.json",
    "src",
    "docs",
  ]) {
    await cp(path.join(projectRoot, entry), path.join(cleanRoot, entry), { recursive: true });
  }
  const npm = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  const npmArgs = (args: string[]) => process.platform === "win32"
    ? ["/d", "/s", "/c", "npm", ...args]
    : args;
  execFileSync(npm, npmArgs(["ci", "--ignore-scripts"]), { cwd: cleanRoot, stdio: "ignore" });
  await mkdir(path.join(cleanRoot, "dist", "src"), { recursive: true });
  await writeFile(path.join(cleanRoot, "dist", "src", "deleted-secret.js"), "stale output\n");
  const output = execFileSync(npm, npmArgs(["pack", "--dry-run", "--json"]), {
    cwd: cleanRoot,
    encoding: "utf8",
  });
  const result = JSON.parse(output) as Array<{ files: Array<{ path: string }> }>;
  const files = result[0]!.files.map((file) => file.path);
  assert.ok(files.includes("dist/src/cli.js"));
  for (const documentation of [
    "README.md",
    "docs/security.md",
    "docs/adr/0001-product-modes-and-trust-boundaries.md",
    "docs/adr/0002-branches-protocols-and-repository-ownership.md",
  ]) {
    assert.ok(files.includes(documentation), `package is missing ${documentation}`);
  }
  assert.ok(files.includes("server-policy.example.json"));
  assert.ok(!files.includes("dist/src/deleted-secret.js"));
});
