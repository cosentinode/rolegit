export default {
  defaultIgnores: false,
  extends: ["@commitlint/config-conventional"],
  parserPreset: {
    parserOpts: {
      headerPattern: /^(\w+)(?:\(([^)\s](?:[^)]*[^)\s])?)\))?(!)?: (\S(?:.*\S)?)$/,
      headerCorrespondence: ["type", "scope", "breaking", "subject"],
    },
  },
};
