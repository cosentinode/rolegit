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
  assert.match(readme, /CI workflows delivered by .*PR #52[\s\S]*pull requests\s+to both `develop` and `main`/);
  assert.match(readme, /not yet trusted, unspoofable enforcement[\s\S]*generic\s+GitHub Actions app[\s\S]*Issue\s+#2.*remains open for secure enforcement/);
  assert.match(readme, /recipient policy does not yet authorize sealing identities or require sealer signatures/);
  assert.match(security, /stale or split view can delay revocation for future seals/);
  assert.match(security, /persisted wrapped DEKs and DEKs already\s+released to clients do not acquire that session expiry/);
  assert.match(security, /legitimate service policy controls only requests that\s+reach it and is not the sole authority for future seals/);
  assert.match(security, /trust repository write controls and Git\s+provenance for content authenticity/);
  assert.match(architecture, /inside Community's authorization-freshness\s+boundary/);
  assert.match(architecture, /removed recipient who retains that private key can later\s+check out and decrypt an older commit/);
  assert.match(architecture, /A sealing device can also decrypt any version whose\s+plaintext DEK it generated or otherwise obtained and retained/);
  assert.match(architecture, /Credentials, sessions, or tokens\s+expire\s+independently/);
  assert.match(architecture, /legitimate server policy is therefore not the sole authority for future seals/);
  assert.match(architecture, /endpoint replacement alone does not reveal objects\s+previously sealed through the expected service/);
  assert.match(architecture, /policy root authorizes recipient state; it does not currently authorize sealing identities/);
  assert.match(architecture, /authenticating an Enterprise B2 provider public wrapping key proves which provider can unwrap a DEK/);
  assert.match(architecture, /neither recipient modes nor B2 local wrap may claim\s+cryptographically authenticated sealer provenance/);
  const diagrams = architecture.match(/```mermaid\r?\n[\s\S]*?\r?\n```/g) ?? [];
  assert.equal(diagrams.length, 6);
  for (const diagram of diagrams) {
    assert.match(diagram, /\|seal:/);
    assert.match(diagram, /\|unlock:/);
    assert.match(diagram, /plaintext-DEK holder/);
  }
  for (const recipientDiagramMarker of [
    "RoleGit Cloud: cannot decrypt; absent from content and key paths",
    "RoleGit Team: metadata only; cannot decrypt",
    "Customer content-blind coordinator: cannot decrypt",
  ]) {
    const recipientDiagram = diagrams.find((diagram) => diagram.includes(recipientDiagramMarker));
    assert.ok(recipientDiagram);
    assert.match(recipientDiagram, /(?:Customer )?[Ss]ealing device: plaintext-DEK holder and decrypt-capable/);
    assert.match(recipientDiagram, /Authorized recovery-key holder: plaintext-DEK holder and decrypt-capable/);
    assert.match(recipientDiagram, /unlock: unwrap plaintext DEK with recovery private key and decrypt locally/);
    assert.match(recipientDiagram, /Repository writer or Git split view/);
    assert.match(recipientDiagram, /can forge a replacement; cannot recover displaced plaintext/);
  }
  const keyProviderDiagram = diagrams.find((diagram) => diagram.includes("Customer key provider or provider-side customer agent"));
  assert.ok(keyProviderDiagram);
  assert.match(keyProviderDiagram, /Authorized client or client-side customer agent/);
  assert.match(keyProviderDiagram, /seal A: request provider-generated DEK/);
  assert.match(keyProviderDiagram, /seal A: return plaintext DEK and wrapped DEK/);
  assert.match(keyProviderDiagram, /seal B1: send client-generated plaintext DEK and context for remote wrap/);
  assert.match(keyProviderDiagram, /seal B1: return wrapped DEK only/);
  assert.match(keyProviderDiagram, /seal B2: authenticated public wrapping key for local wrap; no plaintext DEK received/);
  assert.match(keyProviderDiagram, /Repository writer or Git split view with B2 public wrapping key/);
  assert.match(keyProviderDiagram, /can forge a locally wrapped replacement; cannot recover displaced plaintext/);
  assert.match(keyProviderDiagram, /unlock: return plaintext DEK after authorization/);
  assert.match(architecture, /provider\s+contract requires wrap and unwrap without assuming a\s+provider-specific data-key-generation API/);
  assert.match(architecture, /client-side agent\s+runs in the authorized client boundary/);
  assert.match(architecture, /provider-side agent runs\s+inside the customer provider security boundary/);
  assert.match(architecture, /Provider-generated and remote-wrap sealing place plaintext DEKs inside the provider\/provider-side-agent\s+boundary/);
  assert.match(architecture, /client-side local public-key wrapping does not do so during sealing/);
  assert.match(architecture, /local-wrap variant, it can decrypt immediately after generating the DEK without an unwrap authorization/);
  assert.match(architecture, /unwrap authorization does not establish who sealed\s+the object/);
  assert.match(architecture, /provider policy authorizes requests it receives, while possession of a B2 public wrapping key permits local sealing but does not authorize the sealer or content/);
  assert.match(architecture, /provider revocation cannot affect a client-generated DEK\s+while the client or client-side agent holds or retains it/);
  assert.match(protocols, /silently ignore unknown object fields/);
  assert.match(protocols, /not fail-closed extensibility/);
  assert.match(protocols, /`develop` is the integration branch and the base for feature and maintenance pull requests/);
  assert.match(protocols, /`main` contains stable release history and is the base for reviewed release-promotion pull requests/);
  assert.match(protocols, /PR #52.*delivered CI workflows for pull requests whose\s+base is either `develop` or `main`/);
  assert.match(protocols, /Both bases receive typecheck, build, Ubuntu and Windows tests,\s+package dry-run, CLI smoke/);
  assert.match(protocols, /Branch protection requires those check contexts on both branches/);
  assert.match(protocols, /generic GitHub Actions\s+app[\s\S]*pull-request-controlled workflow can duplicate a required context name/);
  assert.match(protocols, /Issue\s+#2.*remains open for organization-level required\s+workflows or a dedicated least-privilege status producer/);
  assert.match(protocols, /must not claim that\s+either branch has trusted, unspoofable CI enforcement/);
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
  type PackResult = { files: Array<{ path: string }> };
  const parsed = JSON.parse(output) as PackResult[] | Record<string, PackResult>;
  const results = Array.isArray(parsed) ? parsed : Object.values(parsed);
  assert.equal(results.length, 1, "npm pack should describe exactly one package");
  const files = results[0]!.files.map((file) => file.path);
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
