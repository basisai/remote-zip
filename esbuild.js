// @ts-check

// eslint-disable-next-line @typescript-eslint/no-var-requires
const esbuild = require("esbuild");

esbuild.build({
  entryPoints: ["src/index.ts"],
  outdir: "lib",
  bundle: true,
  sourcemap: true,
  minify: true,
  splitting: true,
  format: "esm",
  target: ["chrome94", "firefox96", "safari15", "edge95"],
  watch: process.env["WATCH"] === "1",
});
