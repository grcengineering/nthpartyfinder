# frozen_string_literal: true

# Homebrew CASK for nthpartyfinder (macOS only).
#
# Why a cask exists alongside the formula: only casks may depend on other casks, and that is what
# lets a single `brew install --cask nthpartyfinder` also install Google Chrome. The formula cannot
# — Homebrew forbids a formula depending on a cask — so the formula install path relies on the
# binary's runtime browser prompt instead. Both paths work; the cask is the zero-decision one on
# macOS, and the formula is the only option on Linux (Homebrew has no cask support there).
#
# This file is the SOURCE OF TRUTH, tracked in the product repo. `scripts/sync-homebrew-formula.sh`
# fills in the version and checksums for a release and copies it into the tap. It previously lived
# only as an untracked file inside a local tap checkout, which is why v1.5.0 shipped with no cask
# published at all — nothing in CI could see it, so nothing could notice it was missing.
#
# The version and the two `sha256` values below are rewritten by the sync script; the placeholder
# checksums fail `brew install` and `brew audit` loudly, which is the correct failure mode for a
# placeholder rather than silently installing garbage.
cask "nthpartyfinder" do
  arch arm: "aarch64", intel: "x86_64"

  version "1.6.2"
  sha256 arm:   "e06945a332eb053595a41cec4fb93f4ccfe25f8be28e52529755f004f338d1a3",
         intel: "2b39e1a231972c0866eae7421813f42b24814ed13bc4353aea29794c54a068b3"

  url "https://github.com/grcengineering/nthpartyfinder/releases/download/v#{version}/nthpartyfinder-#{arch}-apple-darwin.tgz",
      verified: "github.com/grcengineering/nthpartyfinder/"
  name "Nth Party Finder"
  desc "CLI tool for identifying Nth party vendor relationships through DNS analysis"
  homepage "https://grc.engineering/"

  # macOS-only: the artifact is a -apple-darwin binary, so `brew readall --os=all` (run by the
  # tap's test-bot) requires an explicit macOS declaration — without it the Linux simulation
  # leaves sha256 nil and the audit fails. Symbol form (`:big_sur`), not the deprecated string
  # comparison form.
  depends_on macos: :big_sur
  depends_on formula: "subfinder"
  depends_on formula: "whois"
  depends_on cask: "google-chrome"

  binary "nthpartyfinder"

  caveats <<~EOS
    nthpartyfinder, subfinder, whois, and Google Chrome are all installed. The binary embeds its
    own data, so it works from any directory — you're ready to run `nthpartyfinder -d example.com`.
  EOS
end
