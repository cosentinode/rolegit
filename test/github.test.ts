import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { createGitHubAppJwt, isActiveTeamMember } from "../src/github.js";

test("GitHub App JWT uses a custom client ID as its issuer", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwt = createGitHubAppJwt(privateKey, "custom-client-id", 1_700_000_000);
  const payload = JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf8")) as {
    iss: string;
  };

  assert.equal(payload.iss, "custom-client-id");
});

test("team checks refresh login and reject reassigned usernames", async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => {
    globalThis.fetch = originalFetch;
  });
  let identity = { id: 101, login: "renamed-user" };
  const membershipUrls: string[] = [];
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const authorization = new Headers(init?.headers).get("authorization");
    if (url === "https://api.github.com/user") {
      assert.equal(authorization, "Bearer user-token");
      return Response.json(identity);
    }
    membershipUrls.push(url);
    assert.equal(authorization, "Bearer installation-token");
    return Response.json({ state: "active" });
  };

  assert.equal(await isActiveTeamMember(
    "user-token",
    "installation-token",
    "acme",
    "operators",
    { id: 101, login: "old-user" },
  ), true);
  assert.match(membershipUrls[0]!, /memberships\/renamed-user$/);

  identity = { id: 202, login: "old-user" };
  assert.equal(await isActiveTeamMember(
    "user-token",
    "installation-token",
    "acme",
    "operators",
    { id: 101, login: "old-user" },
  ), false);
  assert.equal(membershipUrls.length, 1);
});
