// https://docs.expo.dev/guides/using-eslint/  (ESLint 9 flat config)
const expoConfig = require('eslint-config-expo/flat');

module.exports = [
  ...expoConfig,
  {
    ignores: ['dist/*', '.expo/*', 'node_modules/*'],
  },
];
