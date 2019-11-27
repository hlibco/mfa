module.exports = {
  collectCoverage: false,
  coverageDirectory: '../coverage',
  coverageReporters: ['html', 'text', 'lcov'],
  coverageThreshold: {
    global: {
      branches: 25,
      functions: 25,
      lines: 25,
      statements: 25
    }
  },
  forceExit: true,
  // globalSetup: '../jest.setup.js',
  moduleFileExtensions: ['js', 'json', 'ts'],
  notify: true,
  rootDir: '.',
  setupFilesAfterEnv: ['jest'],
  testEnvironment: 'node',
  testPathIgnorePatterns: ['/node_modules/', '/build/', '/coverage/'],
  testURL: 'http://localhost',
  testRegex: '.spec.ts$',
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  verbose: true
}
