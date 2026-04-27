# agent-aws

Lets a developer hand an agent **read-only** access to AWS, even when the
developer themselves has both Administrator and ReadOnly roles assigned via
IAM Identity Center.

📖 **Full documentation:** <https://juanheyns.github.io/agent-aws/>

## Threat model

The threat is *not* the developer — they already have admin. The threat is
the agent being prompt-injected or making a wrong call. Goal: even when the
agent goes off the rails, the worst it can do is read.

The non-obvious risk: setting `AWS_PROFILE=ReadOnly` is *not* sufficient.
The SSO token cached at `~/.aws/sso/cache/<hash>.json` is itself
admin-equivalent — anything that can read it can call
`sso:GetRoleCredentials` against the Administrator role and bypass the
profile entirely. So the agent must be sandboxed *away from* that file.

## Design (layered)

1. **Scoped config.** `agent-aws init` writes `~/.agent-aws/config.json`
   derived from a profile in `~/.aws/config`, hardcoding a non-admin role
   name (default `ReadOnlyAccess`). Init refuses to write a config naming
   any admin-equivalent role.

2. **Cred minting outside the sandbox.** `agent-aws run` reads the
   developer's normal SSO token, calls `sso:GetRoleCredentials` for the
   configured role only, and writes the resulting short-lived STS creds to
   a per-invocation tempdir (`/tmp/agent-aws.XXXX/`).

3. **Sandbox.** The wrapped command runs under a platform-native sandbox
   that denies access to `~/.aws/` and `~/.agent-aws/`. Even if the agent
   or its subprocesses try to read the SSO token, the kernel refuses the
   open before any AWS API call can happen.

   * **macOS:** `sandbox-exec` with the profile in `share/agent-aws.sb` —
     `(deny file-read* (subpath ~/.aws) (subpath ~/.agent-aws))`.
   * **Linux:** `bwrap` (bubblewrap) with `--bind $HOME $HOME --tmpfs ~/.aws
     --tmpfs ~/.agent-aws` — the agent sees those directories as empty.
     Plus `--unshare-pid/ipc/uts` for stronger process isolation than
     macOS provides.

4. **Scoped env.** The sandboxed process is launched with a clean env that
   points `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` at the
   tempdir. `~/.aws/` is effectively invisible.

## Usage

```sh
# One-time bootstrap. Pick which read-only profiles in ~/.aws/config to expose
# to the agent. Admin-equivalent profiles are filtered out.
agent-aws init                          # interactive picker
agent-aws init --all                    # include every non-admin profile
agent-aws init --profile DevReadOnly --profile ProdReadOnly --default DevReadOnly

# Refresh SSO session (interactive, opens browser). With multiple sessions,
# logs into each. Or pin: agent-aws login --session MySsoSession
agent-aws login

# Show configured profiles and which SSO sessions are still valid
agent-aws status

# Sanity check — runs `aws sts get-caller-identity` against the default profile
agent-aws whoami
agent-aws whoami --profile ProdReadOnly

# Run an agent (or any command) with read-only AWS access. By default the
# agent sees ALL configured profiles and can switch between them with
# `aws --profile NAME ...` or AWS_PROFILE=NAME.
agent-aws run -- claude
agent-aws run -- aws s3 ls
agent-aws run -- aws --profile ProdReadOnly ec2 describe-instances

# Lock a single run to one profile — agent cannot reach other accounts
agent-aws run --profile DevReadOnly -- claude
```

Inside the sandbox:

* `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` point at a per-run
  tempdir holding fresh short-lived STS creds for every active profile.
* The default profile is also written as `[default]`, so unflagged
  `aws ...` commands work.
* `AGENT_AWS_PROFILES` and `AGENT_AWS_DEFAULT_PROFILE` env vars expose the
  active set so the agent can introspect what's available.
* `~/.aws/` is unreadable. So is the cached SSO token.
* Each profile's credentials are minted via `sso:GetRoleCredentials` for
  the configured ReadOnly role only — admin role names are rejected at
  init time.

## What this does *not* protect against

* **Data-plane reads.** AWS's managed `ReadOnlyAccess` policy grants
  `s3:Get*`, `dynamodb:GetItem`, etc. If your account has PII or customer
  data, override with a custom control-plane-only policy via
  `agent-aws init --role <CustomReadOnlyRole>`.
* **Kernel exploits / sandbox-exec bugs.** Same caveat as containers; this
  is process isolation, not a separate kernel.
* **Cross-account isolation within a run.** By default `agent-aws run`
  exposes every configured profile so the agent can pick. To hard-pin a
  single account for a particular session, pass `--profile NAME` to
  `agent-aws run` — only that profile's creds will be in the tempdir.

### Files

```
bin/agent-aws        # main wrapper (Python; works on macOS + Linux)
share/agent-aws.sb   # sandbox-exec profile (macOS only)
~/.agent-aws/        # per-user config (mode 700)
  config.json
```

## Platform support

| Platform | Sandbox backend | Required tool |
|---|---|---|
| macOS 12+ | `sandbox-exec` + `share/agent-aws.sb` | built-in |
| Linux (any distro) | `bwrap` (bubblewrap) | `apt install bubblewrap` / `dnf install bubblewrap` / `pacman -S bubblewrap` |

On Linux, unprivileged user namespaces must be enabled. They are by default
on Ubuntu 22.04+, Fedora, Arch, and recent Debian. On hardened/locked-down
distros you may need:

```sh
sudo sysctl kernel.unprivileged_userns_clone=1
```

## Install (development)

```sh
ln -s "$PWD/bin/agent-aws" /usr/local/bin/agent-aws
```

A brew formula is the intended distribution path; not yet built.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for the full list. Short version:

* Long-running broker daemon so `credential_process` can refresh STS creds
  inside the sandbox without the wrapper holding the SSO token in memory.
* Tighter sandbox profile (deny default + explicit allows for
  `process-exec`).
* SCP / permission-boundary template that denies destructive actions for
  sessions tagged `agent=true`, as the AWS-side backstop.
* `agent-gh` and other shims following the same pattern.

## Releasing

Tag-driven via GitHub Actions; pushes a Homebrew formula to
[`juanheyns/homebrew-tap`](https://github.com/juanheyns/homebrew-tap). See
[docs/releasing.md](docs/releasing.md) for the one-time `HOMEBREW_TAP_TOKEN`
secret setup.

## License

[MIT](LICENSE).
