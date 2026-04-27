# Releasing

Releases are driven by git tags. Tagging triggers a GitHub Actions workflow
that renders a Homebrew formula and pushes it to
[`juanheyns/homebrew-tap`](https://github.com/juanheyns/homebrew-tap).

## One-time setup

The release workflow needs write access to a *different* repository
(`juanheyns/homebrew-tap`), so it can't use the default `GITHUB_TOKEN`.

1. Create a fine-grained Personal Access Token:
    - **Repository access:** Only `juanheyns/homebrew-tap`.
    - **Permissions:** *Contents → Read and write*.
2. In `juanheyns/agent-aws` → **Settings → Secrets and variables → Actions
   → New repository secret**, save it as `HOMEBREW_TAP_TOKEN`.

The first release will fail noisily if this is missing, which is the
intended behaviour — better than silently skipping the publish step.

## Cutting a release

The version lives in two places — `pyproject.toml [project].version` and
`bin/agent-aws __version__` — and must be kept in sync. The lint workflow
asserts they match on every push; the release workflow refuses to publish
if either disagrees with the tag.

Use the `scripts/release` helper rather than editing by hand:

```sh
scripts/release patch        # 0.1.0 -> 0.1.1
scripts/release minor        # 0.1.0 -> 0.2.0
scripts/release major        # 0.1.0 -> 1.0.0
scripts/release 1.2.3        # explicit version
```

The script verifies the working tree is clean and you're on `main`, bumps
both files in lockstep, commits with `release vX.Y.Z`, and creates an
annotated tag. By default it stops there and prints the push command:

```sh
git push origin main vX.Y.Z
```

Pass `--push` to push automatically once you're confident in the workflow.

Other useful flags:

| Flag | Purpose |
|---|---|
| `-n` / `--dry-run` | Print what would happen without writing or committing. |
| `--allow-dirty` | Skip the working-tree-clean check. |
| `--allow-branch` | Skip the on-`main` check (e.g. for hotfix branches). |

If you ever need to bypass the script — say a tag was deleted upstream and
you want to re-tag — manually edit both files, commit, and run:

```sh
git tag -a vX.Y.Z -m "agent-aws vX.Y.Z"
git push origin main vX.Y.Z
```

Or via the GitHub UI, **Releases → Draft a new release** with a `vX.Y.Z`
tag.

The `Publish to Homebrew tap` workflow will:

1. Resolve the source tarball URL
   (`https://github.com/juanheyns/agent-aws/archive/refs/tags/vX.Y.Z.tar.gz`).
2. Compute its `sha256`.
3. Render a `Formula/agent-aws.rb` from a template.
4. Commit and push to `juanheyns/homebrew-tap`'s `main` branch with a
   commit message like `agent-aws v0.2.0`.

Users then get the new version via:

```sh
brew update
brew upgrade agent-aws
```

## Re-publishing without a new tag

If you need to re-render the formula (e.g. fixed a bug in the workflow),
the workflow supports `workflow_dispatch` with a `tag` input. Run it from
**Actions → Publish to Homebrew tap → Run workflow** and enter the existing
tag.

## Versioning

Use [SemVer](https://semver.org/). The current pre-1.0 contract:

- Patch (`v0.1.x`): bug fixes, no behaviour changes.
- Minor (`v0.x.0`): new flags or subcommands; existing flags keep their
  behaviour.
- Pre-1.0 minor bumps may include breaking changes to the
  `~/.agent-aws/config.json` schema, with an in-memory migration path
  preserved for at least one minor version.
