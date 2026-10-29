# Contributing

## Releasing Apollo

Apollo uses [Semantic Versioning](https://semver.org/) and annotated Git tags. The Git tag and GitHub Release are the authoritative version; the private `package.json` version only belongs to the test tooling.

Only release commits that are already on `main`. Do not tag a feature branch or move an existing tag.

### Choose the version

Use tags in the form `vMAJOR.MINOR.PATCH`:

- Increment **MAJOR** for breaking template contracts, renamed or removed configuration keys, component or shortcode migrations, and changes to the minimum supported Zola version.
- Increment **MINOR** for backward-compatible features and new optional configuration.
- Increment **PATCH** for bug fixes, documentation corrections, and safe styling changes.

Check the existing releases before choosing a version:

```bash
gh release list --repo not-matthias/apollo
```

### Prepare the release

Create a pull request containing the release changes. Merge it only after the required CI and UI test jobs pass.

If the release updates Zola, keep the versions in `flake.nix` and `Dockerfile.test` identical. Rebuild the container without its cache and confirm its version before running the tests:

```bash
docker-compose -f docker-compose.test.yml build --no-cache playwright-tests
docker-compose -f docker-compose.test.yml run --rm playwright-tests zola --version
```

### Verify the release candidate

Start from an up-to-date `main` branch:

```bash
git switch main
git pull --ff-only origin main
```

Run the local release gates:

```bash
just ci
bun run test:docker-compose
nix develop --command treefmt --fail-on-change
```

For a Zola upgrade, also run:

```bash
nix develop --command zola check
nix flake check --all-systems --no-build
```

Do not continue when a command fails. Fix the failure through another pull request, merge it, update `main`, and rerun the complete release gate.

### Tag and publish

Create an annotated tag on the verified `main` commit:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

Wait for the tag-triggered `CI` workflow to pass. A pushed tag does not create the GitHub Release automatically, so publish it after CI succeeds:

```bash
gh run list --repo not-matthias/apollo --branch vX.Y.Z
gh release create vX.Y.Z \
  --repo not-matthias/apollo \
  --verify-tag \
  --generate-notes \
  --title "vX.Y.Z"
```

Verify the published release:

```bash
gh release view vX.Y.Z --repo not-matthias/apollo
git ls-remote --tags origin vX.Y.Z
```

### Correct a release

Published tags are immutable:

- If only the release notes are wrong, edit the GitHub Release without changing the tag.
- If the tagged code is wrong, merge a fix into `main` and publish the next patch version.
- Never delete, recreate, force-push, or retarget a published tag.
