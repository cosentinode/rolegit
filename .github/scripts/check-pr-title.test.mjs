import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

function check(title) {
  const npm = process.platform === "win32" ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  const args = process.platform === "win32"
    ? ["/d", "/s", "/c", "npm", "run", "lint:commit"]
    : ["run", "lint:commit"];
  return spawnSync(npm, args, {
    encoding: "utf8",
    input: `${title}\n`,
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
    assert.match(`${result.stdout}${result.stderr}`, /found \d+ problems?/);
  }
});
