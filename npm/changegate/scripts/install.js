#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const {
  archiveName,
  artifactBaseURL,
  binaryName,
  ensureExecutable,
  installedBinary,
  normalizeVersion,
  packageRoot,
  parseChecksums,
  releaseTag,
  tempDir,
  vendorDir
} = require("./lib");

async function main() {
  if (truthy(process.env.CHANGEGATE_NPM_SKIP_INSTALL)) {
    return;
  }

  const root = packageRoot();
  fs.rmSync(vendorDir(root), { recursive: true, force: true });
  fs.mkdirSync(vendorDir(root), { recursive: true });

  if (process.env.CHANGEGATE_INSTALL_BINARY) {
    installLocalBinary(process.env.CHANGEGATE_INSTALL_BINARY, root);
    return;
  }

  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const version = normalizeVersion(process.env.CHANGEGATE_VERSION || pkg.version);
  const tag = releaseTag(version);
  const baseURL = artifactBaseURL(tag);
  const archive = archiveName(version);
  const work = tempDir();

  try {
    const checksumsPath = path.join(work, "checksums.txt");
    const archivePath = path.join(work, archive);
    await downloadFile(`${baseURL}/checksums.txt`, checksumsPath);
    await verifyChecksumSignature(baseURL, checksumsPath, tag);
    await downloadFile(`${baseURL}/${archive}`, archivePath);
    verifyChecksum(archivePath, archive, fs.readFileSync(checksumsPath, "utf8"));
    extractArchive(archivePath, work);
    const extracted = findBinary(work);
    if (!extracted) {
      throw new Error(`archive ${archive} did not contain ${binaryName()}`);
    }
    const dest = installedBinary(root);
    fs.copyFileSync(extracted, dest);
    ensureExecutable(dest);
    writeInstallMetadata(root, { version, tag, archive, source: `${baseURL}/${archive}` });
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

function truthy(value) {
  return /^(1|true|yes)$/i.test(String(value || ""));
}

function installLocalBinary(source, root) {
  const absolute = path.resolve(source);
  if (!fs.existsSync(absolute)) {
    throw new Error(`CHANGEGATE_INSTALL_BINARY does not exist: ${absolute}`);
  }
  const dest = installedBinary(root);
  fs.copyFileSync(absolute, dest);
  ensureExecutable(dest);
  writeInstallMetadata(root, { source: absolute, local: true });
}

function writeInstallMetadata(root, metadata) {
  fs.writeFileSync(path.join(vendorDir(root), "install.json"), `${JSON.stringify(metadata, null, 2)}\n`);
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https:") ? https : http;
    const request = client.get(url, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        downloadFile(new URL(response.headers.location, url).toString(), dest).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`download failed for ${url}: HTTP ${response.statusCode}`));
        return;
      }
      const file = fs.createWriteStream(dest, { mode: 0o600 });
      response.pipe(file);
      file.on("finish", () => file.close(resolve));
      file.on("error", reject);
    });
    request.on("error", reject);
  });
}

function verifyChecksum(file, name, checksumsBody) {
  const expected = parseChecksums(checksumsBody).get(path.basename(name));
  if (!expected) {
    throw new Error(`checksums.txt did not include ${name}`);
  }
  const hash = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  if (hash !== expected) {
    throw new Error(`checksum mismatch for ${name}: expected ${expected}, got ${hash}`);
  }
}

async function verifyChecksumSignature(baseURL, checksumsPath, tag) {
  if (falsey(process.env.CHANGEGATE_NPM_VERIFY_SIG)) {
    return;
  }
  const bundlePath = path.join(path.dirname(checksumsPath), "checksums.txt.sigstore.json");
  const sigPath = path.join(path.dirname(checksumsPath), "checksums.txt.sig");
  const certPath = path.join(path.dirname(checksumsPath), "checksums.txt.pem");
  const identity = process.env.CHANGEGATE_COSIGN_CERT_IDENTITY || `https://github.com/Gabriel0110/changegate/.github/workflows/release.yml@refs/tags/${tag}`;
  const issuer = process.env.CHANGEGATE_COSIGN_CERT_OIDC_ISSUER || "https://token.actions.githubusercontent.com";
  const cosign = process.env.CHANGEGATE_COSIGN || "cosign";

  try {
    await downloadFile(`${baseURL}/checksums.txt.sigstore.json`, bundlePath);
    execFileSync(cosign, [
      "verify-blob",
      "--bundle", bundlePath,
      "--certificate-identity", identity,
      "--certificate-oidc-issuer", issuer,
      checksumsPath
    ], { stdio: "pipe" });
    return;
  } catch (error) {
    if (!fs.existsSync(bundlePath)) {
      await downloadFile(`${baseURL}/checksums.txt.sig`, sigPath);
      await downloadFile(`${baseURL}/checksums.txt.pem`, certPath);
      execFileSync(cosign, [
        "verify-blob",
        "--certificate", certPath,
        "--signature", sigPath,
        "--certificate-identity", identity,
        "--certificate-oidc-issuer", issuer,
        checksumsPath
      ], { stdio: "pipe" });
      return;
    }
    throw new Error(`signature verification failed for checksums.txt: ${error.message}`);
  }
}

function falsey(value) {
  return /^(0|false|no)$/i.test(String(value || ""));
}

function extractArchive(archivePath, workDir) {
  const extractDir = path.join(workDir, "extract");
  fs.mkdirSync(extractDir, { recursive: true });
  if (archivePath.endsWith(".tar.gz")) {
    execFileSync("tar", ["-xzf", archivePath, "-C", extractDir], { stdio: "pipe" });
    return;
  }
  if (archivePath.endsWith(".zip")) {
    if (process.platform === "win32") {
      execFileSync("powershell.exe", ["-NoProfile", "-Command", "Expand-Archive", "-LiteralPath", archivePath, "-DestinationPath", extractDir], { stdio: "pipe" });
      return;
    }
    execFileSync("unzip", ["-q", archivePath, "-d", extractDir], { stdio: "pipe" });
    return;
  }
  throw new Error(`unsupported archive format: ${archivePath}`);
}

function findBinary(root) {
  const wanted = binaryName();
  const stack = [path.join(root, "extract")];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile() && entry.name === wanted) {
        return full;
      }
    }
  }
  return "";
}

main().catch((error) => {
  console.error(`ChangeGate npm install failed: ${error.message}`);
  process.exit(1);
});
