import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const checker = fileURLToPath(new URL("check-pr-title.mjs", import.meta.url));

function check(title) {
  return spawnSync(process.execPath, [checker], {
    encoding: "utf8",
    env: { ...process.env, PR_TITLE: title },
  });
}

test("accepts Conventional Commits titles", () => {
  for (const title of [
    "fix: handle missing configuration",
    "feat(cli): add login command",
    "refactor!: remove legacy format",
  ]) {
    assert.equal(check(title).status, 0, title);
  }
});

test("rejects non-Conventional Commits titles", () => {
  for (const title of [
    "Add login command",
    "feature: add login command",
    "fix: ",
  ]) {
    const result = check(title);
    assert.equal(result.status, 1, title);
    assert.match(result.stderr, /Invalid PR title/);
  }
});
