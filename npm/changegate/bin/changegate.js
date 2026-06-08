#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { binaryName, packageRoot } = require("../scripts/lib");

const binary = path.join(packageRoot(), "vendor", binaryName());
const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  if (result.error.code === "ENOENT") {
    console.error("ChangeGate binary is not installed. Reinstall the npm package or run npm rebuild changegate.");
    process.exit(127);
  }
  console.error(result.error.message);
  process.exit(1);
}

if (typeof result.status === "number") {
  process.exit(result.status);
}

process.exit(1);
