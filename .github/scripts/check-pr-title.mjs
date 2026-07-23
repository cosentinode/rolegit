const allowedTypes = [
  "build",
  "chore",
  "ci",
  "docs",
  "feat",
  "fix",
  "perf",
  "refactor",
  "revert",
  "style",
  "test",
];

const title = process.env.PR_TITLE ?? "";
const typePattern = allowedTypes.join("|");
const conventionalCommit = new RegExp(
  `^(?:${typePattern})(?:\\([^)]+\\))?!?: \\S(?:.*\\S)?$`,
);

if (!conventionalCommit.test(title)) {
  console.error(
    `Invalid PR title: "${title}". Use <type>[optional scope][!]: <description>; allowed types: ${allowedTypes.join(", ")}.`,
  );
  process.exitCode = 1;
}
