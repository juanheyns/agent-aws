# Threat model

## What we're defending against

The threat is **not** the human developer. The developer already has admin
access to the account. The threat is the *agent* — Claude or any other
process the developer hands credentials to — being prompt-injected, making a
mistake, or otherwise behaving in ways the developer didn't intend.

Step 1 isolates known credential stores and the listed startup paths. IAM must enforce
read-only permissions; unrestricted network access remains a separate risk.

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

`agent-aws` combines configuration checks, credential minting, filesystem
isolation, and environment scrubbing. These defenses do not replace IAM or
the planned egress lock.

### 1. Scoped configuration

`agent-aws init` writes `~/.agent-aws/config.json` with only non-admin role
names. Init refuses to write a config containing any role whose name matches
`*admin*`, `*poweruser*`, or `*fullaccess*` (case-insensitive).

Every run repeats the blocklist and `allowed_roles` checks for all profiles,
even with `--profile`. Config reads refuse wrong ownership, modes other than
`0600`, and symlinks. Custom names require explicit approval through
`init --role` or a developer edit to `allowed_roles`. This validates names,
not the underlying IAM policy.

### 2. Cred minting outside the sandbox

When the agent runs, the wrapper (running as the developer) reads the SSO
token, calls `sso:GetRoleCredentials` for the configured ReadOnly role, and
writes the resulting short-lived STS credentials to a per-invocation tempdir
at `/tmp/agent-aws.XXXX/`.

The role name passed to `GetRoleCredentials` is hardcoded from
`~/.agent-aws/config.json`, never read from the agent's environment. Before
reading tokens, the wrapper pins the AWS CLI to its resolved absolute path.
The sandbox denies writes to every directory in the launch PATH (including
missing earlier entries), their resolved targets, CLI/interpreter installation
prefixes, and their ancestors. This prevents a run from planting an `aws`
that a later run executes with the SSO token. The developer still supplies a
trusted initial PATH and installation; this is not a scan of pre-existing
executables for malicious content.

Both the source and Homebrew launchers start Python in
[isolated mode (`-I`)](https://docs.python.org/3/using/cmdline.html#cmdoption-I),
so user site-packages startup code (including `.pth` files) and Python
startup environment variables cannot run before the wrapper. The interpreter's
user site-packages directory, resolved target, and ancestors are also protected
against sandbox writes. When invoking the script through Python explicitly,
use `python3 -I bin/agent-aws`; flags in a shebang do not apply to such calls.
Python still executes installation-site `.pth` files in isolated mode.
Every directory returned by `site.getsitepackages()`, its resolved target, and
its ancestors are therefore write-protected, including Homebrew locations
outside `sys.prefix`. The pre-existing installation remains trusted. An AWS
CLI script using a different Python interpreter may load additional site
paths; this separate-interpreter case is tracked in
[issue #4](https://github.com/juanheyns/agent-aws/issues/4).

### 3. Filesystem sandbox

The wrapped command runs under a platform-native sandbox that denies access
to `~/.aws/` and `~/.agent-aws/`:

=== "macOS"

    `sandbox-exec` with `share/agent-aws/agent-aws.sb`:

    ```scheme
    (deny file-read* file-write*
      (subpath (param "HOME_AWS_DIR"))
      (subpath (param "AGENT_DIR")))
    ```

    The static profile is combined with generated path rules. Protected
    paths and their resolved targets deny writes; every ancestor has a literal
    write deny to stop rename-and-restore attacks while leaving ordinary
    siblings writable. The launcher path and interpreter are included.
    Other runs' files deny both reads and writes; only this run's credential
    directory gets an exception. Metadata lookup is allowed only for run
    directory names and their `credentials`/`config` files so the spec's glob
    reports denied reads. Contents and directory listings remain denied.

    Even reads via symlink are blocked by belt-and-braces regex denies on
    `*/.aws/sso/cache/*.json` and `*/.aws/credentials`.

=== "Linux"

    `bwrap` (bubblewrap) hides credential directories behind empty read-only
    mounts and makes startup files read-only. A private home-directory skeleton
    prevents missing startup files from being planted persistently. Existing
    project directories remain writable; see [platform support](platform-support.md).

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

- **Other persistence classes.** Git/SSH configuration, agent settings and
  hooks, executable directories outside the launch PATH, and mutable Homebrew
  dependencies outside protected installation prefixes remain gaps. The PATH
  used by a later unsandboxed invocation can also differ. This is protection
  for the listed paths, not complete host isolation. Follow-up:
  [remaining host persistence paths](https://github.com/juanheyns/agent-aws/issues/4).

- **Found credentials and local services.** Network access remains open.
  Credentials in project files, metadata services, and reachable unsandboxed
  daemons are not blocked by step 1. The broker and egress lock are separate work.
- **Session renewal.** Credentials are still static for a run. The planned
  broker will renew them; this change does not extend their lifetime.

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
