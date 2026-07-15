import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createGitHubAppJwt } from "../src/github.js";

test("GitHub App JWT uses a custom client ID as its issuer", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwt = createGitHubAppJwt(privateKey, "custom-client-id", 1_700_000_000);
  const payload = JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf8")) as {
    iss: string;
  };

  assert.equal(payload.iss, "custom-client-id");
});
