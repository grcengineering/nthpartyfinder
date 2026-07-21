# frozen_string_literal: true

# Homebrew formula for nthpartyfinder: discover Nth-party vendor relationships via DNS
# analysis. Installs the same signed, SLSA-provenance-tracked, embedded-NER release
# artifact release.yml produces — not a from-source build. Checksums below are filled in
# by scripts/sync-homebrew-formula.sh once a release with matching tarballs actually
# exists (placeholders fail `brew install`/`brew audit` loudly, which is the correct
# failure mode for a placeholder rather than silently installing garbage).
#
# All runtime dependencies install automatically. `whois` and `subfinder` are formulae
# (both platforms); Google Chrome is a macOS cask (Homebrew on Linux has no cask support,
# so Linux users install Chromium/Chrome from their distro — see caveats). The binary
# ships every data file it needs embedded, so no config directory is required.
class Nthpartyfinder < Formula
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering"
  version "1.5.0"
  license "MIT"

  depends_on "subfinder"
  depends_on "whois"

  # Google Chrome powers web-content, web-traffic, and subprocessor-render discovery.
  # It is a cask, which only exists on macOS; guard so the formula still resolves on Linux.
  on_macos do
    depends_on cask: "google-chrome"
  end

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.5.0/nthpartyfinder-aarch64-apple-darwin.tgz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.5.0/nthpartyfinder-x86_64-apple-darwin.tgz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  elsif OS.linux?
    url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.5.0/nthpartyfinder-x86_64-unknown-linux-gnu.tgz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    bin.install "nthpartyfinder"
  end

  def caveats
    <<~EOS
      subfinder, whois, and (on macOS) Google Chrome install automatically; all data files are
      embedded in the binary.

      macOS: if the install stops on an existing "Google Chrome" that Homebrew did not manage,
      adopt it once, then re-run the install:
        brew install --cask --adopt google-chrome

      Linux: Homebrew cannot install Chrome (it is a macOS-only cask) — install Chrome or Chromium
      from your distribution for web-content/web-traffic/subprocessor-render discovery, e.g.:
        sudo apt-get install chromium   # or google-chrome-stable
      Everything else still installs automatically; without a browser those phases are skipped and
      the scan still runs.
    EOS
  end

  test do
    assert_match "nthpartyfinder", shell_output("#{bin}/nthpartyfinder --version")
    assert_match "Usage:", shell_output("#{bin}/nthpartyfinder --help")
  end
end
