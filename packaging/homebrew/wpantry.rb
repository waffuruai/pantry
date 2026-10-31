# The formula waffuruai/homebrew-tap carries (`brew install waffuruai/tap/wpantry`).
# It installs the release binaries this repository's release workflow built and
# attested; nothing is compiled. The version is the tag in each `url` (Homebrew
# reads it from there). `packaging/homebrew/bump.sh` rewrites the tag and the
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
      url "https://github.com/waffuruai/pantry/releases/download/v0.2.0/wpantry-universal-apple-darwin"
      sha256 "738c8cf5974bce607d71dab3795db0b70e569374d28046a0cbde47409bc626bc" # wpantry-universal-apple-darwin
    end
    on_intel do
      url "https://github.com/waffuruai/pantry/releases/download/v0.2.0/wpantry-universal-apple-darwin"
      sha256 "738c8cf5974bce607d71dab3795db0b70e569374d28046a0cbde47409bc626bc" # wpantry-universal-apple-darwin
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/waffuruai/pantry/releases/download/v0.2.0/wpantry-x86_64-unknown-linux-musl"
      sha256 "9b35d7a5fbe5a5a838aa146bd3cafa6fdb9486e6dcd1036c87f899048f132f28" # wpantry-x86_64-unknown-linux-musl
    end
    on_arm do
      url "https://github.com/waffuruai/pantry/releases/download/v0.2.0/wpantry-aarch64-unknown-linux-musl"
      sha256 "9b33af2b9bb0b70f9cb7a63e0a540c5d128964c36c1343cbb232cf644959a033" # wpantry-aarch64-unknown-linux-musl
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
