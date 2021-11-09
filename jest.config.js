const config = {
  transform: {
    "^.+\\.tsx?$": [
      "esbuild-jest",
      {
        sourcemap: true,
        loaders: {
          ".test.ts": "tsx",
        },
      },
    ],
  },
};

module.exports = config;
