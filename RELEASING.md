# Releasing nthpartyfinder

This is the maintainer runbook for cutting a release. There was no documented process before
this file — everything below reflects what `.github/workflows/release.yml` and
`.github/workflows/docker.yml` actually do, not aspiration.

## Before you tag

1. **Add a CHANGELOG entry.** `release.yml`'s `create-draft` job hard-fails if
   `nthpartyfinder/CHANGELOG.md` has no `## [x.y.z]` header matching the tag — this is enforced,
   not a suggestion. Follow the existing Keep-a-Changelog format (`### Added`/`### Security`/etc.).
2. **Bump the version** in `nthpartyfinder/Cargo.toml` (`[package] version`) to match. Run
   `cargo build --locked` once so `Cargo.lock` picks up the bump.
3. **Run the local gates** (same ones CI enforces): `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
   the full test suite, `cargo deny check`. See `CONTRIBUTING.md` for exact commands.
4. Commit (signed — code commits need your Secretive-key tap, never self-signed by an agent),
   push, open a PR, and get CI green before tagging.

## Cutting the GitHub release

```sh
git tag v1.4.0 <commit>
git push origin v1.4.0
```

Pushing a `v*` tag triggers `release.yml`, which (per platform target — linux-gnu, macos x64/arm64,
windows-msvc):

1. Creates a **draft** release (GitHub's immutable-releases feature forbids asset changes after
   publish, so every artifact lands on a draft first; the release only goes live in the last step).
2. Builds the offline `embedded-ner` binary and packages it as a `.tgz` (all platforms) plus, where
   applicable:
   - **Linux**: `.deb` (`cargo-deb`) and `.rpm` (`cargo-generate-rpm`), packaging the *same*
     already-built binary (`--no-build` / no rebuild) — never a second, differently-featured build.
   - **Windows**: `.zip` (native `Compress-Archive`) and a best-effort `.msi`
     (`cargo-wix`, `continue-on-error: true` — this is a newer, less-proven step; a failure there
     does not block the release). **Known asymmetry**: the `.msi` uses cargo-wix's own default
     build, which is the crate's default `runtime-ner` feature (model fetched on first run) — not
     the offline `embedded-ner` build every other artifact ships. Documented, not accidental.
3. Generates a **CycloneDX SBOM** (Syft) and a **keyless Sigstore signature** (cosign) for every
   artifact produced.
4. Aggregates the primary `.tgz` digests across all 4 platforms and emits **SLSA Build L3
   provenance** via `slsa-github-generator`.
5. Attaches everything to the still-draft release, then publishes it (`--draft=false --latest`).

Watch it: `gh run watch` or `gh pr checks` on the tag's workflow run. If anything fails, fix and
re-push the tag (delete + re-push, or a new patch tag) — don't leave a broken draft lying around.

## Docker (already automatic)

`docker.yml` builds and pushes to `ghcr.io/grcengineering/nthpartyfinder` on the *same* tag push —
no separate action needed. Two images: the default (embedded NER) and `:slim` (no embedded NER,
`Dockerfile.dev`). Both now carry buildx-native SLSA provenance + SBOM attestation.

## crates.io

Publishing is **deliberately separate** from the tag push — it's irreversible (a version can be
yanked, never removed) and uses crates.io **Trusted Publishing (OIDC)**, not a stored token
(`CARGO_REGISTRY_TOKEN` does not exist as a secret in this repo, by design).

**One-time setup** (before the first publish): configure trusted publishing at
<https://crates.io/crates/nthpartyfinder/settings> (or via crates.io's new-crate trusted-publishing
flow if the crate has never been published), naming this repo, the `release.yml` workflow, and the
`release` GitHub Environment.

**To publish a release that's already live on GitHub:**

```sh
gh workflow run release.yml --ref v1.4.0 -f tag=v1.4.0
```

This runs the `publish-crate` job only (the tag-push jobs are skipped on `workflow_dispatch`). It
runs `cargo publish --dry-run` first as a sanity gate, then the real `cargo publish`. Verify locally
first if you want extra confidence: `cd nthpartyfinder && cargo package --list` /
`cargo publish --dry-run`.

## Homebrew

A maintained, **shared** tap for all GRC Engineering tools —
[`grcengineering/homebrew-grcengineering`](https://github.com/grcengineering/homebrew-grcengineering)
(`Formula/nthpartyfinder.rb`), not `homebrew-core` and not a project-specific tap — installs the
same signed release binary, not a from-source build:

```sh
brew tap grcengineering/grcengineering
brew install nthpartyfinder
```

The formula declares `subfinder` and `whois` as dependencies (installed automatically), so a plain
`brew install` produces a working tool with no manual dependency installation. The binary embeds all
of its own data (vendor registry, known-vendors, SaaS platforms) so no `config/` directory is
shipped or needed. **A browser is NOT a formula dependency** — Homebrew formulae cannot depend on a
cask (`depends_on cask:` is rejected by `brew audit`/`test-bot` as an invalid formula dependency),
and there is no cask: shipping one would break `brew install --cask` on machines that already have
Chrome and would not work on Linux at all. Instead the binary handles the browser at runtime — a
scan that needs one and finds none offers to install it for the user's platform (`--install-browser`
skips the prompt), and any existing browser is detected and used. So the tap ships **one formula**,
installable on macOS and Linux with a single `brew install nthpartyfinder`. The first `brew install`
from a fresh machine prints a one-time trust prompt — `brew tap` above runs `brew trust` for you on
current Homebrew, or run `brew trust grcengineering/grcengineering` manually.

After a release's `build-release` matrix has finished (the tarballs must exist to hash):

```sh
nthpartyfinder/scripts/sync-homebrew-formula.sh v1.4.0
```

This downloads each platform tarball, computes real sha256 checksums, updates
`nthpartyfinder/packaging/homebrew/nthpartyfinder.rb` locally, verifies it with `brew style`, and —
if the tap repo is reachable via your `gh` auth — pushes the updated formula there (into `Formula/`,
alongside any other GRC Engineering tool formulas). If the tap repo isn't reachable, it stops after
the local update and tells you so.

## WinGet

Manifests are prepared under `packaging/winget/manifests/g/GRCEngineering/NthPartyFinder/<version>/`
(version, installer, and `en-US` locale YAML, matching the winget-pkgs repo's own layout and
schema — validated against the real `1.12.0` JSON schemas, not just hand-written). **Publishing is
a manual PR to `microsoft/winget-pkgs`, not automated** — that's a third-party review process, not
something to script.

Before submitting for a new version:

1. Copy the previous version's manifest dir to a new `<version>/` dir, bump `PackageVersion` in all
   3 files and the `.../nthpartyfinder-x86_64-pc-windows-msvc.zip` URL.
2. Fill in the real `InstallerSha256` (currently a placeholder) — download the released `.zip` and
   `shasum -a 256` it, or use `winget-create update` if you have `wingetcreate` installed.
3. Fork `microsoft/winget-pkgs`, copy the manifest dir into the fork at the same path, open a PR.
   (`wingetcreate submit` can automate this if you have a GitHub token with fork/PR rights.)

## Supply-chain notes

- Every new action referenced above is SHA-pinned, matching this repo's existing convention
  (`# vX.Y.Z` comment for readability; Dependabot keeps pins current). The one pre-existing sanctioned
  exception (`slsa-github-generator`, pinned by tag not SHA — its TUF trust model requires it) is
  unchanged.
- `cargo publish`/crates.io uses OIDC trusted publishing — no long-lived registry token exists in
  this repo's secrets.
- Every release artifact (not just the primary `.tgz`) is now individually Sigstore-signed — each
  gets a `.bundle` file (the current Sigstore-recommended combined format: signature + certificate
  + transparency-log entry). Verify with
  `cosign verify-blob --bundle <file>.bundle --certificate-identity-regexp 'https://github.com/grcengineering/nthpartyfinder/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
  This is in addition to (not a replacement for) the `.tgz`-scoped SLSA provenance attestation
  (`slsa-verifier verify-artifact`) — two different, complementary guarantees; verify whichever
  fits your threat model.

## Known follow-ups (not blocking, tracked here so they aren't lost)

- The `.msi` installer step is best-effort on its first real run (can't be tested outside GitHub's
  Windows runners) — watch the first live run closely.

## Governance

The branch-protection ruleset's `OrganizationAdmin` bypass was removed 2026-07-20 — org admins can
no longer skip the 12 required status checks on `master` (previously `bypass_mode: always`; now
`bypass_actors: []`). This means merges, including this repo owner's own, are unconditionally
gated on CI passing.
