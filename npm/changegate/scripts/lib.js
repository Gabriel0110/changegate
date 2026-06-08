"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function packageRoot() {
  return path.resolve(__dirname, "..");
}

function binaryName(platform = process.platform) {
  return platform === "win32" ? "changegate.exe" : "changegate";
}

function platformTarget(platform = process.platform, arch = process.arch) {
  const osMap = new Map([
    ["darwin", "darwin"],
    ["linux", "linux"],
    ["win32", "windows"]
  ]);
  const archMap = new Map([
    ["x64", "amd64"],
    ["arm64", "arm64"]
  ]);
  const goos = osMap.get(platform);
  const goarch = archMap.get(arch);
  if (!goos || !goarch) {
    throw new Error(`unsupported platform ${platform}/${arch}; supported targets are darwin, linux, and windows on x64 or arm64`);
  }
  return { goos, goarch };
}

function normalizeVersion(version) {
  const cleaned = String(version || "").trim().replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(cleaned)) {
    throw new Error(`invalid ChangeGate version ${JSON.stringify(version)}`);
  }
  return cleaned;
}

function releaseTag(version, env = process.env) {
  if (env.CHANGEGATE_RELEASE_TAG) {
    return env.CHANGEGATE_RELEASE_TAG;
  }
  return `v${normalizeVersion(version)}`;
}

function archiveName(version, platform = process.platform, arch = process.arch) {
  const { goos, goarch } = platformTarget(platform, arch);
  const suffix = goos === "windows" ? "zip" : "tar.gz";
  return `changegate_${normalizeVersion(version)}_${goos}_${goarch}.${suffix}`;
}

function artifactBaseURL(tag, env = process.env) {
  if (env.CHANGEGATE_RELEASE_BASE_URL) {
    return env.CHANGEGATE_RELEASE_BASE_URL.replace(/\/$/, "");
  }
  return `https://github.com/Gabriel0110/changegate/releases/download/${tag}`;
}

function parseChecksums(body) {
  const out = new Map();
  for (const line of String(body).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const match = /^([a-fA-F0-9]{64})\s+\*?(.+)$/.exec(trimmed);
    if (!match) {
      continue;
    }
    out.set(path.basename(match[2].trim()), match[1].toLowerCase());
  }
  return out;
}

function vendorDir(root = packageRoot()) {
  return path.join(root, "vendor");
}

function installedBinary(root = packageRoot(), platform = process.platform) {
  return path.join(vendorDir(root), binaryName(platform));
}

function ensureExecutable(file) {
  if (process.platform !== "win32") {
    fs.chmodSync(file, 0o755);
  }
}

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "changegate-npm-"));
}

module.exports = {
  archiveName,
  artifactBaseURL,
  binaryName,
  ensureExecutable,
  installedBinary,
  normalizeVersion,
  packageRoot,
  parseChecksums,
  platformTarget,
  releaseTag,
  tempDir,
  vendorDir
};
