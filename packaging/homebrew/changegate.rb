class Changegate < Formula
  desc "Graph-aware Terraform/OpenTofu deployment risk gate"
  homepage "https://github.com/Gabriel0110/changegate"
  version "X.Y.Z"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/changegate_X.Y.Z_darwin_arm64.tar.gz"
      sha256 "DARWIN_ARM64_SHA256"
    else
      url "https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/changegate_X.Y.Z_darwin_amd64.tar.gz"
      sha256 "DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/changegate_X.Y.Z_linux_arm64.tar.gz"
      sha256 "LINUX_ARM64_SHA256"
    else
      url "https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/changegate_X.Y.Z_linux_amd64.tar.gz"
      sha256 "LINUX_AMD64_SHA256"
    end
  end

  def install
    bin.install "changegate"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/changegate version")
  end
end
