module.exports = {
  reporters: ['default', 'jest-junit'],
  roots: ['<rootDir>'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  },
  testMatch: ['<rootDir>/test/**/*.(test|spec).ts'],
  testTimeout: 10000
};
