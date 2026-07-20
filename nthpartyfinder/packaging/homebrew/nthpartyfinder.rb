# frozen_string_literal: true

# Homebrew formula for nthpartyfinder: discover Nth-party vendor relationships via DNS
# analysis. Installs the same signed, SLSA-provenance-tracked, embedded-NER release
# artifact release.yml produces — not a from-source build. Checksums below are filled in
# by scripts/sync-homebrew-formula.sh once a release with matching tarballs actually
# exists (placeholders fail `brew install`/`brew audit` loudly, which is the correct
# failure mode for a placeholder rather than silently installing garbage).
class Nthpartyfinder < Formula
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering"
  version "1.4.0"
  license "MIT"

  depends_on "whois"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.4.0/nthpartyfinder-aarch64-apple-darwin.tgz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.4.0/nthpartyfinder-x86_64-apple-darwin.tgz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  elsif OS.linux?
    url "https://github.com/grcengineering/nthpartyfinder/releases/download/v1.4.0/nthpartyfinder-x86_64-unknown-linux-gnu.tgz"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  end

  def install
    bin.install "nthpartyfinder"
  end

  def caveats
    <<~EOS
      Optional dependencies for full functionality:

      For web content analysis (--enable-web-org, --enable-web-traffic-discovery):
        brew install --cask google-chrome

      For subdomain discovery (--enable-subdomain-discovery):
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    EOS
  end

  test do
    assert_match "nthpartyfinder", shell_output("#{bin}/nthpartyfinder --version")
    assert_match "Usage:", shell_output("#{bin}/nthpartyfinder --help")
  end
end
