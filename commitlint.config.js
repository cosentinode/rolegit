export default {
  defaultIgnores: false,
  extends: ["@commitlint/config-conventional"],
  parserPreset: {
    parserOpts: {
      headerPattern: /^(\w+)(?:\(([^)]+)\))?(!)?: (.+)$/,
      headerCorrespondence: ["type", "scope", "breaking", "subject"],
    },
  },
};
