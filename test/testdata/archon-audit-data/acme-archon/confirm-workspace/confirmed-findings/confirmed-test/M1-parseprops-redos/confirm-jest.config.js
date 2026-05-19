module.exports = {
  rootDir: '../../..',
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
  moduleNameMapper: { '\\.(css|less)$': '<rootDir>/src/empty.js' },
  testMatch: ['**/archon/findings/M1-parseprops-redos/confirm-test.ts'],
};
