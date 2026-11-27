# The formula waffuruai/homebrew-tap carries (`brew install waffuruai/tap/wpantry`).
# It installs the release binaries this repository's release workflow built and
# attested; nothing is compiled. The version is the tag in each `url` (Homebrew
# reads it from there). `rust/release/homebrew-bump.sh` rewrites the tag and the
# digests from a release's SHA256SUMS, and the release
# workflow's `tap` job opens the bump PR on the tap (docs/internal/release.md).
class Wpantry < Formula
  desc "Vulnerability scanner for what is installed and what your repos lock"
  homepage "https://github.com/waffuruai/pantry"
  license "MIT"

  livecheck do
    url :homepage
    strategy :github_latest
  end

  # One macOS binary serves both CPUs (a universal build), so the two blocks
  # name the same asset.
  on_macos do
    on_arm do
      url "https://github.com/waffuruai/pantry/releases/download/v0.10.0/wpantry-universal-apple-darwin"
      sha256 "d95ecdae7a895602f81f1a5e089af3097aa18dc4e8aad7e88d6af1003d9f6056" # wpantry-universal-apple-darwin
    end
    on_intel do
      url "https://github.com/waffuruai/pantry/releases/download/v0.10.0/wpantry-universal-apple-darwin"
      sha256 "d95ecdae7a895602f81f1a5e089af3097aa18dc4e8aad7e88d6af1003d9f6056" # wpantry-universal-apple-darwin
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/waffuruai/pantry/releases/download/v0.10.0/wpantry-x86_64-unknown-linux-musl"
      sha256 "f6956ea38b076d2c34291ab0bd56e10645674d8a40607365fba274e0f1321a9d" # wpantry-x86_64-unknown-linux-musl
    end
    on_arm do
      url "https://github.com/waffuruai/pantry/releases/download/v0.10.0/wpantry-aarch64-unknown-linux-musl"
      sha256 "d2601e67603cd3818b62c173bbfebda9e7c7ae4d98e9a3b28090747828d5a62c" # wpantry-aarch64-unknown-linux-musl
    end
  end

  def install
    # One binary is downloaded, named for its target; it becomes `wpantry`.
    bin.install Dir["wpantry-*"].fetch(0) => "wpantry"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/wpantry version")
    # An empty directory, offline: nothing applies, so the check exits 0 (its
    # warnings about unreachable sources are not failures).
    (testpath/"empty").mkpath
    ENV["WPANTRY_DB"] = testpath/"cache/wpantry.db"
    system bin/"wpantry", "check", "--no-machine", "--offline", "--no-input", "--path", testpath/"empty"
  end
end
