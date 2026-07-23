# frozen_string_literal: true

# Homebrew formula for nthpartyfinder: discover Nth-party vendor relationships via DNS
# analysis. Installs the same signed, SLSA-provenance-tracked, embedded-NER release
# artifact release.yml produces — not a from-source build. Checksums below are filled in
# by scripts/sync-homebrew-formula.sh once a release with matching tarballs actually
# exists (placeholders fail `brew install`/`brew audit` loudly, which is the correct
# failure mode for a placeholder rather than silently installing garbage).
#
# The formula dependencies `subfinder` and `whois` install automatically (both platforms), and the
# binary ships every data file it needs embedded, so no config directory is required. A browser
# (Chrome/Chromium/Edge) is NOT a formula dependency — Homebrew formulae cannot depend on a cask,
# and a browser isn't needed for the default run. Instead the binary handles it at runtime: the
# first scan that needs a browser and finds none offers to install one for the user's platform
# (`--install-browser` skips the prompt), and any existing browser is detected and used. See
# `caveats`.
class Nthpartyfinder < Formula
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering"
  # No explicit `version`: Homebrew scans it from the release URL's `/vX.Y.Z/` path, and an explicit
  # `version` that matches is a `brew audit` error (redundant-with-URL). sync-homebrew-formula.sh
  # bumps the version by rewriting the URL path, so the version tracks the URL automatically.
  license "MIT"

  depends_on "subfinder"
  depends_on "whois"

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
      subfinder and whois were installed automatically, and all data files are embedded in the
      binary — nthpartyfinder is ready to use.

      The browser-based discovery methods (web-content, web-traffic, and subprocessor-render) use
      Chrome, Chromium, or Edge. You do not need to install one now: the first scan that needs a
      browser and finds none will offer to install one for you (Google Chrome via Homebrew here on
      macOS; Chromium via your package manager on Linux). Pass --install-browser to install without
      prompting in unattended runs, or decline the prompt and those phases run with reduced coverage
      — the scan never hangs. Any browser you already have is detected and used automatically.
    EOS
  end

  test do
    assert_match "nthpartyfinder", shell_output("#{bin}/nthpartyfinder --version")
    assert_match "Usage:", shell_output("#{bin}/nthpartyfinder --help")
  end
end
