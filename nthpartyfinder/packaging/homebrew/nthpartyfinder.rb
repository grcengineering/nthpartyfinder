class Nthpartyfinder < Formula
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://github.com/grcengineering/nthpartyfinder"
  url "https://github.com/grcengineering/nthpartyfinder/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "MIT"

  depends_on "rust" => :build
  depends_on "whois"

  def install
    # Build with all default features including embedded NER
    cd "nthpartyfinder" do
      system "cargo", "build", "--release"
      bin.install "target/release/nthpartyfinder"
    end
  end

  def post_install
    # Download ONNX Runtime for NER support
    ohai "Setting up ONNX Runtime for NER organization extraction..."
    system bin/"nthpartyfinder", "--version"
  end

  def caveats
    <<~EOS
      ONNX Runtime is required for NER organization extraction.
      On first run, nthpartyfinder will prompt to download it (~7-15 MB).
      Or run: scripts/install.sh to set up ONNX Runtime in advance.

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
