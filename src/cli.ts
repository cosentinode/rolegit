#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

import { createAuthServer, decodeKeyEncryptionKey } from "./auth-server.js";
import {
  initialize,
  lock,
  lockIfSessionExpired,
  login,
  printStatus,
  protect,
  seal,
  unlock,
} from "./commands.js";
import { repositoryRoot } from "./files.js";
import { GitHubAppClient } from "./github.js";
import { loadEnclist, parseServerPolicy } from "./policy.js";
import { repositoryId } from "./session.js";

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

function help(): void {
  console.log(`RoleGit - role-based encrypted files for Git

Usage:
  rolegit init --server <url>
  rolegit protect <path>
  rolegit login [--development-user <numeric-id>]
  rolegit status
  rolegit seal [path...]
  rolegit unlock [path...]
  rolegit lock
  rolegit serve --policy <file> [--port 8787]

Environment for serve:
  ROLEGIT_KEK       Base64url-encoded 32-byte key-encryption key
  ROLEGIT_GITHUB_APP_KEY  Path to the GitHub App private-key PEM
  ROLEGIT_DEV_AUTH  Set to 1 to enable explicitly configured development users`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args.shift();
  if (!command || command === "help" || command === "--help" || command === "-h") {
    help();
    return;
  }

  if (command === "__expire") {
    const [root, expectedExpiry] = args;
    if (!root || !expectedExpiry || args.length !== 2) throw new Error("invalid expiry watcher arguments");
    await lockIfSessionExpired(root, expectedExpiry);
    return;
  }

  if (command === "serve") {
    const policyPath = option(args, "--policy");
    const portText = option(args, "--port") ?? "8787";
    if (!policyPath || args.length > 0) throw new Error("serve requires --policy <file>");
    const port = Number(portText);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("invalid port");
    const kekText = process.env.ROLEGIT_KEK;
    if (!kekText) throw new Error("ROLEGIT_KEK is required");
    const policy = parseServerPolicy(JSON.parse(await readFile(path.resolve(policyPath), "utf8")));
    const githubAppKeyPath = process.env.ROLEGIT_GITHUB_APP_KEY;
    const githubApp = githubAppKeyPath
      ? new GitHubAppClient(await readFile(path.resolve(githubAppKeyPath)), policy.githubClientId)
      : undefined;
    const server = createAuthServer({
      policy,
      keyEncryptionKey: decodeKeyEncryptionKey(kekText),
      allowDevelopmentAuth: process.env.ROLEGIT_DEV_AUTH === "1",
      ...(githubApp === undefined ? {} : { githubApp }),
    });
    server.listen(port, "127.0.0.1", () => {
      console.log(`RoleGit authorization service listening on http://127.0.0.1:${port}`);
    });
    return;
  }

  const root = repositoryRoot();
  if (command === "init") {
    const server = option(args, "--server");
    if (!server || args.length > 0) throw new Error("init requires --server <url>");
    await initialize(root, server);
    return;
  }
  if (command === "protect") {
    if (args.length !== 1) throw new Error("protect requires exactly one path");
    await protect(root, args[0]!);
    return;
  }

  if (command === "lock") {
    if (args.length > 0) throw new Error("lock does not accept arguments");
    await lock(root);
    return;
  }

  const policy = await loadEnclist(root);
  if (command === "login") {
    const developmentUserText = option(args, "--development-user");
    if (args.length > 0) throw new Error("unexpected login arguments");
    const developmentUser = developmentUserText === undefined ? undefined : Number(developmentUserText);
    if (developmentUser !== undefined && !Number.isSafeInteger(developmentUser)) {
      throw new Error("--development-user must be a numeric GitHub user ID");
    }
    await login(root, policy.authServer, developmentUser);
    return;
  }
  if (command === "status") {
    if (args.length > 0) throw new Error("status does not accept arguments");
    await printStatus(root, policy.authServer);
    return;
  }
  if (command === "seal") {
    await seal(root, args);
    return;
  }
  if (command === "unlock") {
    const session = await unlock(root, args);
    const identity = repositoryId(root);
    const watcherTarget = /^[a-f0-9]{64}$/.test(identity) ? root : identity;
    const child = spawn(process.execPath, [process.argv[1]!, "__expire", watcherTarget, session.expiresAt], {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    console.log(`Access expires at ${session.expiresAt}; run \`rolegit lock\` when finished.`);
    return;
  }
  throw new Error(`unknown command: ${command}`);
}

main().catch((error: unknown) => {
  console.error(`error: ${(error as Error).message}`);
  process.exitCode = 1;
});
