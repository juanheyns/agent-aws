# Threat model

## What we're defending against

The threat is **not** the human developer. The developer already has admin
access to the account. The threat is the *agent* — Claude or any other
process the developer hands credentials to — being prompt-injected, making a
mistake, or otherwise behaving in ways the developer didn't intend.

Goal: even when the agent goes off the rails, the worst it can do is read.

## What we're *not* defending against

`agent-aws` is not a sandbox for the human. A sufficiently determined
developer can trivially bypass any of these layers with their own admin
credentials. The protections only apply to processes the developer
*explicitly* launches via `agent-aws run`.

## The non-obvious risk

Setting `AWS_PROFILE=ReadOnly` for an agent process is **not sufficient**.

The SSO token cached at `~/.aws/sso/cache/<hash>.json` is itself
admin-equivalent. Any process that can read that file can call:

```sh
aws sso get-role-credentials \
  --role-name AdministratorAccess \
  --account-id <whatever> \
  --access-token "$(jq -r .accessToken < ~/.aws/sso/cache/...json)"
```

…and bypass the profile entirely. So credential isolation requires
*physical* isolation from that file, not just configuration plumbing.

## Layered defenses

`agent-aws` stacks four independent defenses, each of which alone would be
sufficient to block an agent from gaining admin credentials.

### 1. Scoped configuration

`agent-aws init` writes `~/.agent-aws/config.json` with only non-admin role
names. Init refuses to write a config containing any role whose name matches
`*admin*`, `*poweruser*`, or `*fullaccess*` (case-insensitive).

This is the baseline correctness check — even a misconfigured machine can't
accidentally hand the agent admin scope.

### 2. Cred minting outside the sandbox

When the agent runs, the wrapper (running as the developer) reads the SSO
token, calls `sso:GetRoleCredentials` for the configured ReadOnly role, and
writes the resulting short-lived STS credentials to a per-invocation tempdir
at `/tmp/agent-aws.XXXX/`.

The role name passed to `GetRoleCredentials` is hardcoded from
`~/.agent-aws/config.json`, never read from the agent's environment.

### 3. Filesystem sandbox

The wrapped command runs under a platform-native sandbox that denies access
to `~/.aws/` and `~/.agent-aws/`:

=== "macOS"

    `sandbox-exec` with `share/agent-aws/agent-aws.sb`:

    ```scheme
    (deny file-read*
      (subpath (param "HOME_AWS_DIR"))
      (subpath (param "AGENT_DIR")))
    ```

    Even reads via symlink are blocked by belt-and-braces regex denies on
    `*/.aws/sso/cache/*.json` and `*/.aws/credentials`.

=== "Linux"

    `bwrap` (bubblewrap) with `--bind $HOME $HOME` plus `--tmpfs ~/.aws
    --tmpfs ~/.agent-aws`. The agent literally sees those directories as
    empty — there is nothing to read.

    Also `--unshare-pid --unshare-ipc --unshare-uts`: the agent is PID 1 in
    its own namespace and can't enumerate host processes that might be
    holding credentials in memory.

If the agent or any of its subprocesses tries to `open(2)` the SSO cache,
the kernel returns `EPERM` before the AWS API call ever happens.

### 4. Scoped environment

The sandboxed process is launched with a clean environment. `AWS_CONFIG_FILE`
and `AWS_SHARED_CREDENTIALS_FILE` point at the per-run tempdir; `~/.aws/`
isn't even on the agent's mental map.

## Validation

You can confirm the layers are in place by running adversarial commands
inside the sandbox:

```sh
agent-aws run -- /bin/sh -c '
  echo "=== read SSO cache ==="
  ls ~/.aws/sso/cache/
  cat ~/.aws/sso/cache/*.json

  echo "=== read agent-aws state ==="
  cat ~/.agent-aws/config.json

  echo "=== try a write ==="
  aws iam create-user --user-name agent-pwn

  echo "=== try assume-role to admin ==="
  aws sts assume-role \
    --role-arn arn:aws:iam::ACCOUNT:role/AdministratorAccess \
    --role-session-name pwn
'
```

All four should fail — the first two with kernel `EPERM`, the last two with
IAM `AccessDenied`.

## Out of scope

These are real risks `agent-aws` does *not* address:

- **Data-plane reads.** AWS's managed `ReadOnlyAccess` policy grants
  `s3:Get*`, `dynamodb:GetItem`, etc. If your account has PII or customer
  data, override at init time with a custom control-plane-only policy:

    ```sh
    agent-aws init --role MyControlPlaneReadOnly
    ```

- **Kernel exploits / sandbox bugs.** `sandbox-exec` and `bwrap` are
  process-level isolation, not separate kernels. A kernel-level CVE escapes
  both. Same caveat as Docker.

- **Cross-account isolation within a run.** By default `agent-aws run`
  exposes every configured profile so the agent can pick. To hard-pin a
  single account for a particular session:

    ```sh
    agent-aws run --profile ProdReadOnly -- claude
    ```

    Only that profile's creds are in the tempdir; no other profile is
    reachable.

- **Defense in depth at the AWS side.** A future iteration will publish an
  SCP / permission-boundary template that denies destructive actions for
  sessions tagged `agent=true`, as a final backstop. See the
  [roadmap](roadmap.md).
