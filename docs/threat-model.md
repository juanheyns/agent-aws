# Threat model

## What we're defending against

The threat is **not** the human developer. The developer already has admin
access to the account. The threat is the *agent* — Claude or any other
process the developer hands credentials to — being prompt-injected, making a
mistake, or otherwise behaving in ways the developer didn't intend.

Step 1 isolates known credential stores and the listed startup paths. It is
**not** full host isolation: see the
[supported host-isolation boundary](#supported-host-isolation-boundary). IAM must
enforce read-only permissions; unrestricted network access remains a separate risk.

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
outside `sys.prefix`. The pre-existing installation remains trusted. When the
resolved `aws` is a Python script for a different interpreter (for example
`pip install --user awscli`), the wrapper asks that interpreter (`-I -S`) for
its prefixes, site-packages and user site and protects them too. If it cannot
answer, the run fails closed. The interpreter is read from a direct shebang,
from `env` (with `-i`, `-u`, `-S`, `-P` and `NAME=VALUE`), or from the
pip/distlib `#!/bin/sh` + `'''exec' <python>` launcher; `python*` and `pypy*`
names are followed. Before Python 3.11, `-I -S` reports the base install for
a venv interpreter, so the venv root (the interpreter's `../..` when a
`pyvenv.cfg` is next to it or one level up, for the lexical and the resolved
path) is protected as well, and `pyvenv.cfg` cannot be created there. This
covers an `aws` wrapper outside the venv whose shebang names the venv's
Python. HOME and its ancestors are never protected as a whole.
`aws` wrappers that are not Python scripts (asdf or mise shims, shell scripts)
and shebangs that cannot be parsed are not followed; for a Python-like
shebang that cannot be parsed, agent-aws prints a warning
([#12](https://github.com/juanheyns/agent-aws/issues/12)).

Homebrew prefixes are user-writable. PATH symlinks such as
`/opt/homebrew/bin/git` resolve into `Cellar/`. The Homebrew Python loads
shared libraries through `opt/` (for example `liblzma` and `libzstd`) before the
wrapper reads the SSO token. Every top-level entry of a Homebrew prefix (a
directory with `Cellar/`) above a protected path is therefore write-protected,
except `var/`, which holds service data.

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

## Supported host-isolation boundary

The threat here is *persistence*: a run writes something that a later,
unsandboxed process (the developer's shell, git, ssh, an agent session, or the
next `agent-aws run` wrapper) executes. That process can read
`~/.aws/sso/cache` and get admin credentials. Step 1 blocks this for a fixed
list of known paths. It does not block it in general.

### Protected (write-denied on macOS, read-only or private on Linux)

- Credential stores: `~/.aws` and `~/.agent-aws` (also unreadable), and other
  runs' `/tmp/agent-aws.*` directories.
- Shell startup files: `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `.zlogout`,
  `.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`.
- Launch and autostart directories: `~/Library/LaunchAgents`,
  `~/.config/systemd/user`, `~/.config/autostart`, and `~/.config/brnr`.
- Git and SSH configuration: `~/.gitconfig`, `~/.config/git`, `~/.ssh/config`,
  `~/.ssh/rc`, `~/.ssh/authorized_keys`, `~/.ssh/authorized_keys2`. Agents can
  still read them, run git, and append to `~/.ssh/known_hosts`.
- Files and programs that this git and SSH configuration refers to: include
  targets, the `core.hooksPath` directory, helper programs given as absolute
  or `~` paths, and `$XDG_CONFIG_HOME/git` and `$GIT_CONFIG_GLOBAL`. See
  [git and SSH config targets](#git-and-ssh-config-targets).
- Claude Code settings and hooks: `~/.claude/settings.json` and
  `~/.claude/settings.local.json`. Claude Code session state
  (`~/.claude/projects` and similar) stays writable. Settings changes made
  inside a run fail; change them outside the sandbox.
- Executables and code that the wrapper or a later shell runs: every
  launch-PATH directory, the agent-aws installation and launcher, the Python
  interpreter, its site-packages and user site, the `aws` and `python3`
  installation prefixes, the interpreter paths of a Python `aws` script
  (including the venv of a venv interpreter), and
  each Homebrew prefix except `var/`.
- For each path: its resolved symlink target. On macOS every ancestor is also
  protected against rename.

Missing paths in this list cannot be created: macOS denies the write, and on
Linux the new file is private to the run.

### Git and SSH config targets

Before the sandbox starts, and outside it, agent-aws finds the files and
programs that the global git config and `~/.ssh/config` refer to, and protects
them ([#6](https://github.com/juanheyns/agent-aws/issues/6)). A target that
does not exist yet is protected too, so a run cannot create it. HOME and its
ancestors are never protected. A target outside HOME follows the same rules as
the other protected paths: on macOS writes to it are denied; on Linux it is
read-only when it is in a read-only system mount, and not visible in the run
otherwise.

**Git.** agent-aws runs the `git` that it finds in the launch PATH. It uses a
minimal environment (HOME, PATH, `GIT_CONFIG_NOSYSTEM=1`, no pager, no
prompt), an empty working directory outside any repository, and a 10-second
timeout. `git config --list` only reads config. It does not run helpers,
pagers or hooks (a unit test checks this).

- The start files are `~/.gitconfig`, `~/.config/git/config`, and also
  `$XDG_CONFIG_HOME/git/config` and `$GIT_CONFIG_GLOBAL` when these are set in
  the environment of `agent-aws`. The `$XDG_CONFIG_HOME/git` directory and the
  `$GIT_CONFIG_GLOBAL` file are protected.
- Each file is read separately with `--no-includes`. Every `include.path` and
  `includeIf.*.path` is followed, whatever its condition, up to git's include
  depth of 10. `git config --global --list --show-origin --includes` adds the
  files that git itself includes.
- Protected from these files:
    - every included file. `~` is expanded. A relative path is relative to the
      directory of the including file (its lexical and its resolved path).
    - the `core.hooksPath` directory, when it is absolute or starts with `~`.
    - the program of a command when its first word is an absolute or `~` path
      (after a `!` and a leading `exec`): `credential.helper` (also per URL),
      `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.editor`,
      `core.askPass`, `core.gitProxy`, `sequence.editor`, `gpg.program` and
      `gpg.*.program`, `diff.external`, `diff.*.textconv`, `diff.*.command`,
      `filter.*.clean`, `filter.*.smudge`, `filter.*.process`,
      `merge.*.driver`, `cmd` and `path` of `mergetool.*`, `difftool.*`,
      `man.*` and `browser.*`, `sendemail.smtpServer`,
      `uploadpack.packObjectsHook`, `pager.*` and `alias.*`.
- If git is not in PATH, or a git call fails or times out, the run continues
  and prints a warning. The targets of that config are then not protected.

**SSH (partial parse).** agent-aws does not run `ssh -G`, because it
evaluates `Match exec`, which runs commands. agent-aws reads `~/.ssh/config`
itself:

- What is parsed: `Include` lines in any `Host` or `Match` block, recursively up
  to ssh's depth of 16. `~` is expanded, and a relative path is relative to
  `~/.ssh`. For a glob, agent-aws protects the matched files and the directory
  above the first glob part, so that a new match cannot be planted. The
  exception is `~/.ssh` itself (`known_hosts` must stay writable). Also parsed:
  the first word of `ProxyCommand`, `LocalCommand`, `KnownHostsCommand` and
  `Match [!]exec` when it is an absolute or `~` path (a leading `exec` is
  skipped), and the `PKCS11Provider` and `SecurityKeyProvider` libraries.
- What is not parsed: `/etc/ssh/ssh_config` and its includes, files given with
  `ssh -F`, `%` tokens and `${VAR}` in paths, other keywords (for example
  `IdentityAgent` or `UserKnownHostsFile`), and lines that `shlex` cannot split.

**Not protected.** A command that is a shell string (`!sh -c '…'`,
`ProxyCommand sh -c …`, a shell function, a variable) cannot be resolved in
general. Only its first word is checked, and a bare name resolves through the
protected PATH. These are also not protected: a relative `core.hooksPath`
(git resolves it in each repository), the system git config and its includes,
`%(prefix)/` include paths, repository config
([#7](https://github.com/juanheyns/agent-aws/issues/7)), and, on macOS, a new
file that matches a glob `Include` directly in `~/.ssh` (on Linux, `~/.ssh` is
a private skeleton, so the new file disappears after the run).

#### What normal use now breaks inside a run

- You cannot edit an included git config file, a script in the
  `core.hooksPath` directory, or a helper program that the config names. Also,
  `git config --file <include target> …` fails, and a new hook cannot be added.
  Make these changes outside the sandbox.
- A dotfiles repository that holds an include target or a helper: that file
  is read-only in a run, so a `git pull` or `checkout` there that changes it
  fails. On Linux, the directory that holds a target becomes a private
  skeleton: existing entries stay writable, but new top-level entries there
  disappear when the run ends.
- A global `core.hooksPath` or a helper path inside a project makes that path
  read-only in the run. On Linux the project directory then becomes a private
  skeleton too: new top-level entries in it disappear when the run ends.
- New files cannot be added to a directory that a glob `Include` reads, for
  example `~/.ssh/config.d`.

### Not protected

The [#4 assessment](https://github.com/juanheyns/agent-aws/pull/5) confirmed
with disposable fixtures that a run can still write these. Each one is tracked:

| Class | Example that stays writable | Issue |
|---|---|---|
| Install targets of symlinked PATH executables | `~/.local/share/claude/versions/*` behind `~/.local/bin/claude` | [#13](https://github.com/juanheyns/agent-aws/issues/13) |
| Git/SSH commands that are shell strings, and config that agent-aws does not parse | `!sh -c '…'` aliases, `ProxyCommand sh -c …`, a relative `core.hooksPath`, system git config, `/etc/ssh/ssh_config`, ssh `${VAR}` paths | [#6](https://github.com/juanheyns/agent-aws/issues/6) (decision: not resolvable in general; see [git and SSH config targets](#git-and-ssh-config-targets)) |
| Repository-local configuration | `.git/config` (`core.fsmonitor`), `.git/hooks`, project `.claude/settings.json`, `.envrc` | [#7](https://github.com/juanheyns/agent-aws/issues/7) |
| Agent config that the agent writes itself | `~/.claude.json` (`mcpServers`), `~/.claude/plugins`, `~/.claude/CLAUDE.md`, `~/.codex/config.toml` | [#8](https://github.com/juanheyns/agent-aws/issues/8) |
| Code sourced by startup files, other shells, tool config, other bin dirs | `~/.oh-my-zsh/custom`, `~/.config/fish`, `~/.npmrc`, `~/bin` not in PATH | [#9](https://github.com/juanheyns/agent-aws/issues/9) |
| Mutable dependencies outside protected trees | Homebrew `var/`, new prefix entries, nvm, uv, conda, mise | [#10](https://github.com/juanheyns/agent-aws/issues/10) |
| macOS services that write for the caller, app autostart | cfprefsd (Terminal/iTerm2 startup command), Login Items, launchd jobs, iTerm2 AutoLaunch | [#11](https://github.com/juanheyns/agent-aws/issues/11) |
| `aws` wrappers that are not Python scripts, shebangs that cannot be parsed | asdf/mise shims, shell wrappers, `#!python3` (relative) | [#12](https://github.com/juanheyns/agent-aws/issues/12) |

The working tree is output of an untrusted process. Review it before you run
git, build tools, or an agent in it outside the sandbox. A later unsandboxed
invocation can also use a different PATH from the one that was protected.
Files that the sandbox can read, such as SSH private keys, are not protected
against exfiltration while the network is open.

### Decision: deny-list, not host isolation

We compared three options:

1. **Wider protected roots** (for example all of HOME, `~/.local` or
   `~/Library`). This breaks agents, which must write caches, session state
   and the working tree. Also, the list of roots that later processes execute
   has no end: each entry in the table above is a different tool's
   convention. We use wider roots only where a root is an install tree that a
   run does not need to write: the Homebrew prefix without `var/`. Installs
   into protected PATH directories already fail inside a run.
2. **Separate OS user.** The agent runs as a user that has no write access to
   the developer's HOME, keychain, Homebrew prefix or launchd/cfprefsd domain.
   This removes the whole class, not a list of paths.
3. **Container or VM** (rootless podman, Lima, Apple `container`). Like a
   separate user, and it also separates the kernel view. The cost is a
   project mount and agent setup inside the box.

Step 1 stays a deny-list of known startup paths. It is documented as
protection for those paths, not as host isolation. It is a good default for an
agent that you mostly trust and want to stop from making mistakes or from
being prompt-injected into the most common persistence paths. For agents that
you do not trust, use a separate OS user or a container/VM as the boundary
([#14](https://github.com/juanheyns/agent-aws/issues/14)). The egress lock
(step 3) is still necessary in both cases.

## Out of scope

These are real risks `agent-aws` does *not* address:

- **Persistence outside the listed paths.** See
  [not protected](#not-protected) above. This is protection for the listed
  paths, not complete host isolation.

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
