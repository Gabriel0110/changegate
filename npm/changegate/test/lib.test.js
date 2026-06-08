"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  archiveName,
  normalizeVersion,
  parseChecksums,
  platformTarget,
  releaseTag
} = require("../scripts/lib");

test("platformTarget maps supported Node platforms to Go release targets", () => {
  assert.deepEqual(platformTarget("darwin", "arm64"), { goos: "darwin", goarch: "arm64" });
  assert.deepEqual(platformTarget("darwin", "x64"), { goos: "darwin", goarch: "amd64" });
  assert.deepEqual(platformTarget("linux", "arm64"), { goos: "linux", goarch: "arm64" });
  assert.deepEqual(platformTarget("linux", "x64"), { goos: "linux", goarch: "amd64" });
  assert.deepEqual(platformTarget("win32", "x64"), { goos: "windows", goarch: "amd64" });
});

test("platformTarget rejects unsupported targets", () => {
  assert.throws(() => platformTarget("freebsd", "x64"), /unsupported platform/);
  assert.throws(() => platformTarget("linux", "riscv64"), /unsupported platform/);
});

test("archiveName matches GoReleaser artifact names", () => {
  assert.equal(archiveName("0.3.0", "darwin", "arm64"), "changegate_0.3.0_darwin_arm64.tar.gz");
  assert.equal(archiveName("v0.3.0", "linux", "x64"), "changegate_0.3.0_linux_amd64.tar.gz");
  assert.equal(archiveName("0.3.0", "win32", "x64"), "changegate_0.3.0_windows_amd64.zip");
});

test("releaseTag defaults to v-prefixed package version", () => {
  assert.equal(releaseTag("0.3.0", {}), "v0.3.0");
  assert.equal(releaseTag("0.3.0", { CHANGEGATE_RELEASE_TAG: "nightly" }), "nightly");
});

test("normalizeVersion validates release versions", () => {
  assert.equal(normalizeVersion("v0.3.0"), "0.3.0");
  assert.equal(normalizeVersion("0.3.0"), "0.3.0");
  assert.throws(() => normalizeVersion("latest"), /invalid ChangeGate version/);
});

test("parseChecksums reads sha256sum output", () => {
  const checksums = parseChecksums("abc0000000000000000000000000000000000000000000000000000000000000  changegate_0.3.0_linux_amd64.tar.gz\n");
  assert.equal(checksums.get("changegate_0.3.0_linux_amd64.tar.gz"), "abc0000000000000000000000000000000000000000000000000000000000000");
});
