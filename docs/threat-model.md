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
that a later run executes with the SSO token. When the `aws` or `python3`
prefix (the `../..` of the resolved executable) is HOME or an ancestor of
HOME, only the executable's directory is protected, so HOME stays writable;
if that directory is itself HOME or an ancestor of HOME, only the executable
is protected. In that case, `python3`'s own install paths (stdlib,
site-packages, as its `-I -S` probe reports them, minus HOME and its
ancestors) are protected too; the other directories of that prefix (for
`aws`, or non-Python files) are not. HOME is compared both as given and
resolved. The agent-aws interpreter's own prefix (`sys.prefix`, `sys.base_prefix`) is protected
without this HOME rule: if that prefix is HOME's parent, HOME stays
write-denied (fail-safe). Every symlink on the chain from the `agent-aws`,
`aws` and `python3` PATH entries to their targets is protected too, also directory
links in the middle (for example `current -> releases/1`), so a run cannot
repoint a link in a writable directory (`<PATH>/aws -> ~/link -> …`) to its
own file ([#23](https://github.com/juanheyns/agent-aws/issues/23)). The link
itself is protected, not its directory and not its target (a `/tmp` link
does not protect `/private/tmp`). Links that are HOME or an ancestor of HOME,
or whose target is, are skipped (for example `/var -> private/var` on macOS,
or a symlinked HOME). More than 40 links on one path fail closed.
The developer still supplies a trusted initial PATH and installation; this
is not a scan of pre-existing executables for malicious content.

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
- User-level agent instructions: `~/.claude/CLAUDE.md`, `~/.claude/agents`,
  `~/.claude/commands`, `~/.claude/skills`, `~/.codex/AGENTS.md` and
  `~/.codex/AGENTS.override.md`. Other `~/.claude` and `~/.codex` entries stay
  writable.
- Programs that the user-level agent config names: Claude Code hook,
  `statusLine` and helper commands, MCP server commands in `~/.claude.json`,
  and Codex `mcp_servers` and `notify` programs. See
  [agent instructions and config programs](#agent-instructions-and-config-programs).
- Other shells' and tools' startup code: fish `~/.config/fish/config.fish`,
  `conf.d`, `functions` and `completions`; `~/.oh-my-zsh/custom`,
  `~/.zpreztorc`, `~/.inputrc`, `~/.npmrc`, `~/.config/starship.toml`,
  `~/.config/direnv`, `~/.tmux.conf`, `~/.config/tmux/tmux.conf`, `~/.vimrc`,
  `~/.vim/vimrc`, `~/.config/vim/vimrc`, `~/.config/nvim/init.lua` and `init.vim`, IPython
  `profile_default/startup` and `ipython_config.py`, and the file that
  `$PYTHONSTARTUP` names. See
  [shell and tool startup code](#shell-and-tool-startup-code).
- Executables and code that the wrapper or a later shell runs: every
  launch-PATH directory, the agent-aws installation and launcher, the Python
  interpreter, its site-packages and user site, the `aws` and `python3`
  installation prefixes, the interpreter paths of a Python `aws` script
  (including the venv of a venv interpreter), and
  each Homebrew prefix except `var/`.
- The install location of the run's own command (`agent-aws run -- claude`):
  the symlinks on its PATH chain and its install prefix. See
  [the run's own command](#the-runs-own-command).
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
    - the `core.hooksPath` and `init.templateDir` directories, when the path
      is absolute or starts with `~`. `git init` and `git clone` copy the hooks
      in the template directory into each new repository.
    - the program of a command when its first word is an absolute or `~` path
      (after a `!` and a leading `exec`): `credential.helper` (also per URL),
      `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.editor`,
      `core.askPass`, `core.gitProxy`, `core.alternateRefsCommand`,
      `hook.*.command`, `sequence.editor`, `gpg.program`, `gpg.*.program`,
      `gpg.ssh.defaultKeyCommand`, `interactive.diffFilter`,
      `diff.external`, `diff.*.textconv`, `diff.*.command`,
      `filter.*.clean`, `filter.*.smudge`, `filter.*.process`,
      `merge.*.driver`, `cmd` and `path` of `mergetool.*`, `difftool.*`,
      `man.*` and `browser.*`, `sendemail.smtpServer`, `sendemail.sendmailCmd`,
      `sendemail.toCmd`, `sendemail.ccCmd`, `sendemail.headerCmd`,
      `trailer.*.command`, `trailer.*.cmd`, `remote.*.uploadpack`,
      `remote.*.receivepack`, `uploadpack.packObjectsHook`, `pager.*` and
      `alias.*`.
    - This key list is not complete forever. New git versions add keys whose
      value is a command, and agent-aws does not protect a key that is not in
      the list (`GIT_COMMAND_KEYS` in `bin/agent-aws`).
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
or `init.templateDir` (git resolves them in each repository or working directory), the system git config and its includes,
`%(prefix)/` include paths, repository config
([#7](https://github.com/juanheyns/agent-aws/issues/7)), and, on macOS, a new
file that matches a glob `Include` directly in `~/.ssh` (on Linux, `~/.ssh` is
a private skeleton, so the new file disappears after the run).

### Agent instructions and config programs

Later, unsandboxed Claude Code and Codex sessions load user-level
instructions and start the programs that their config names
([#8](https://github.com/juanheyns/agent-aws/issues/8)). The agents write
their config files themselves during a normal session, so **the config files
stay writable**: `~/.claude.json`, `~/.codex/config.toml`, `~/.codex/auth.json`,
`~/.claude/plugins`, session state and history. agent-aws protects:

- The instruction files and directories in the [protected list](#protected-write-denied-on-macos-read-only-or-private-on-linux).
  A missing one cannot be created in a run, except on Linux for
  `~/.codex/AGENTS.md` and `~/.codex/AGENTS.override.md` (see
  [what normal use now breaks](#what-normal-use-now-breaks-inside-a-run)).
- The programs that this config names, read before the sandbox starts and
  outside it. Nothing is executed. HOME and its ancestors are never protected.
    - `~/.claude/settings.json` and `settings.local.json`: every hook
      `command`, `statusLine.command`, `apiKeyHelper`, `awsAuthRefresh`,
      `awsCredentialExport` and `otelHeadersHelper`. These are shell commands:
      the first word is used when it is an absolute or `~` path (a leading
      `exec` is skipped, and a leading `$HOME/`, `${HOME}/`, `"$HOME"/` or
      `"${HOME}"/` counts as `~/`).
    - `~/.claude.json`: `mcpServers.*.command`, at the top level and in
      `projects.*.mcpServers`.
    - `~/.codex/config.toml`: `mcp_servers.*.command` and `notify[0]`. This
      needs `tomllib` (Python 3.11 or later).
    - The program of an MCP server or `notify` is one word; an absolute or `~`
      path is used as it is.
- A file that cannot be read or parsed, or Python without `tomllib`: the run
  continues and prints a warning. The programs of that file are then not
  protected.

**Not protected.** The config files themselves: `~/.claude.json` and
`~/.codex/config.toml` stay writable, so a run can add a new `mcpServers` or
`notify` entry that points to any program, and the next unsandboxed session
starts it. Protecting the named programs only stops changes to programs that
the config already names (and on Linux it adds skeletons, see below).
`@path` imports in `~/.claude/CLAUDE.md` (for example
`@~/notes/agent-rules.md`): later sessions load the imported files as
instructions, but agent-aws does not read the imports, so these files stay
writable. `~/.claude/plugins/**` stays
writable: Claude Code writes it to install and update plugins, and plugin
hooks, MCP servers and commands live in the same trees, so no read-only
subset is safe without a test with the real agent. Also not protected: a
bare program name (it resolves through the protected PATH), an interpreter
with a script argument (`bash ~/x.sh`, `node ~/x.js`: only `bash` or `node` is
checked), other shell syntax, `$CLAUDE_PROJECT_DIR` hooks and other project
config ([#7](https://github.com/juanheyns/agent-aws/issues/7)),
`~/.claude/output-styles`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME` (agent-aws
reads only `~/.claude` and `~/.codex`), and other agents (not surveyed).

### Shell and tool startup code

Later, unsandboxed shells and tools run code from more files than the shell
rc files ([#9](https://github.com/juanheyns/agent-aws/issues/9)). This list
has no end, and each entry costs legitimate use, so agent-aws protects only
files that a tool reads as code at startup and that the tool does not write in
normal use:

| Protected | Runs when | Legitimate use that fails in a run |
|---|---|---|
| `~/.config/fish/config.fish`, `conf.d`, `functions`, `completions` | every fish shell | editing fish config; `fisher install`/`update` and `funcsave` (they write `functions`, `conf.d`, `completions`) |
| `~/.oh-my-zsh/custom` | every zsh with oh-my-zsh | adding or editing custom plugins and themes |
| `~/.zpreztorc` | every zsh with prezto | editing the prezto config |
| `~/.inputrc` | every readline program (a key macro can type a command) | editing readline bindings |
| `~/.npmrc` | every `npm`/`npx` (`node-options`, `script-shell`) | `npm login`, `npm adduser`, `npm logout`, `npm config set`/`delete` |
| `~/.config/starship.toml` | every prompt (custom `command` modules) | editing the prompt config |
| `~/.config/direnv` | every `.envrc` (`direnvrc`, `lib/*.sh`; `direnv.toml` `whitelist` trusts `.envrc` files) | editing direnv config; the allow list (`~/.local/share/direnv`) stays writable |
| `~/.tmux.conf`, `~/.config/tmux/tmux.conf` | every tmux server (`run-shell`, `if-shell`) | editing tmux config; `~/.tmux/plugins` stays writable |
| `~/.vimrc`, `~/.vim/vimrc`, `~/.config/vim/vimrc`, `~/.config/nvim/init.lua`, `init.vim` | every vim/nvim (vim reads the first of the three vimrc files that exists, so a missing one is protected too) | editing them. Not protected: `~/.vim/plugin/*.vim`, `~/.vim/pack/*/start/` and nvim `~/.config/nvim/plugin/` (and `lua/`, `lazy-lock.json`) stay writable, and vim/nvim run that code at every start |
| IPython `~/.ipython/profile_default/startup`, `ipython_config.py` | every IPython | adding startup scripts; `ipython profile create` for the default profile |
| the absolute path in `$PYTHONSTARTUP` at launch | every interactive Python | editing that file |

These stay writable because the tools write them: fish `fish_variables`
(`set -U`, and fish writes it at startup), the oh-my-zsh checkout and its
`cache` (auto-update runs `git pull` in `~/.oh-my-zsh`; it does not touch
`custom` while upstream does not change its tracked example files there), `~/.zprezto` (`zprezto-update`), nvim `lazy-lock.json` and IPython
history.

**Not protected.** agent-aws does not parse rc files for `source` lines: the
set of files that they can load has no end. So these stay writable: files that
a protected rc file sources (`~/.zsh/*.zsh`, a dotfiles repository), the
oh-my-zsh core files (`oh-my-zsh.sh`, `lib`, `plugins`, `themes`: a run can
change them, and the next zsh runs them), the `~/.zprezto` checkout, zsh plugin
managers (antigen, zinit, zplug, antidote), fish `fish_variables` (a
universal `fish_user_paths` or `fish_function_path` changes what later fish
shells run) and `fish_plugins` (the next `fisher update` installs from it),
nushell and xonsh config, `~/.tmux/plugins`, vim/nvim plugins and `lua/`
modules, other editor and tool init that is not in the table, a `PYTHONSTARTUP`
that a later shell sets differently, `ZDOTDIR` and `XDG_CONFIG_HOME` other than
the defaults, and bin directories that are not in the launch PATH (`~/bin`,
`~/go/bin`, `~/.npm-global/bin`), which a later shell with a different PATH
runs. For these, use the
[strong boundary](#supported-host-isolation-boundary)
([#14](https://github.com/juanheyns/agent-aws/issues/14)).

### The run's own command

Agent CLIs are often installed as a symlink in a PATH directory into a
writable install tree in HOME
([#13](https://github.com/juanheyns/agent-aws/issues/13)). The PATH
directory is protected, but the target was not, so a run could replace the
`claude` binary that the developer next starts unsandboxed. Before the
sandbox starts, agent-aws finds the run's command (`args[0]`) in PATH, as the
shell does (a name with a `/` is relative to the current directory), and
protects:

- Every symlink on the way to the executable (file links and directory links
  in the middle), as for `aws` above.
- The first of its resolved install prefix (`../..`), bin directory and
  executable that is allowed by the rules below.

Examples: `~/.local/bin/claude -> ~/.local/share/claude/versions/2.1.301`
protects the link and `~/.local/share/claude`. The Codex standalone install
(`~/.local/bin/codex -> ~/.codex/packages/standalone/current/bin/codex`, with
`current -> releases/0.160.1-aarch64-apple-darwin`) protects the link,
`current` and `releases/0.160.1-aarch64-apple-darwin`.

Never protected (a link to one of them is skipped too):

- HOME, `/` and the other ancestors of HOME (as given and resolved). So
  `/bin/sh` protects `/bin` on macOS and `/usr` on Linux, and `~/tool`
  protects only the executable.
- The working tree: the current directory (as given and resolved), the
  nearest ancestor with a `.git` entry (found without running git), their
  ancestors and everything inside them. So `./script` or `../tools/x` in the
  project makes nothing in the project read-only. When the current directory
  is HOME or an ancestor of HOME, or the `.git` is in HOME (a dotfiles
  repository), only the HOME rule applies.

Still not protected:

- Other executables in PATH that are not the run's command, for example the
  target of `~/.local/bin/codex` when you run `claude`. A later unsandboxed
  `codex` can start a binary that this run replaced.
- A command started through a wrapper: `sh -c 'claude'`, `env X=1 claude`,
  `npx …`, `uvx …`. Only `args[0]` is followed.
- The interpreter and libraries of a script command (for example the `node`
  that a `#!/usr/bin/env node` command runs, and its `node_modules`).
- A command inside the working tree: it is output of the run anyway.

### What normal use now breaks inside a run

- You cannot edit an included git config file, a script in the
  `core.hooksPath` or `init.templateDir` directory, or a helper program that the config names. Also,
  `git config --file <include target> …` fails, and a new hook cannot be added.
  Make these changes outside the sandbox.
- A dotfiles repository that holds an include target or a helper: that file
  is read-only in a run, so a `git pull` or `checkout` there that changes it
  fails.
- **On Linux, every directory between HOME and a target becomes a private
  skeleton**, not only the directory that holds the target. This is also true
  when the target is missing. In each of these directories:
    - new top-level entries are lost when the run ends. For example, with an
      include target `~/Source/github.com/me/dotfiles/git-extra`, `~/Source`,
      `~/Source/github.com`, `~/Source/github.com/me` and
      `~/Source/github.com/me/dotfiles` are skeletons, so a `git clone` into
      `~/Source/github.com/<new-owner>/` is lost when the run ends.
    - an existing top-level entry is a bind mount, so it cannot be replaced by
      rename and cannot be unlinked (`EBUSY`). Changes below it stay writable.
- Common cases: `[includeIf "gitdir:~/work/"]` with
  `path = ~/work/.gitconfig` makes `~/work` a skeleton, also when
  `~/work/.gitconfig` does not exist yet. A global `core.hooksPath`,
  `init.templateDir` or helper path inside a project makes that path
  read-only, and the project directory and its parents below HOME become
  skeletons.
- At run start on Linux, agent-aws prints the skeleton directories that come
  from git, SSH and agent config targets (`agent-aws: Linux: new top-level
  entries in these directories are lost when the run ends (they hold protected
  git/ssh/agent config, $PYTHONSTARTUP or the run's command): …`). Create new projects outside these directories, or move the
  target out of the project tree.
- Why every directory between HOME and the target: a read-only bind of only
  the target, in a read-write parent, is not sufficient. Linux refuses to
  rename a mount point (`EBUSY`), but it lets a process rename a directory
  above a mount point. A run could rename a parent directory, create the
  parent again and write a new file at the target path, and that file stays
  on the host. In the skeleton chain, each directory between HOME and the
  target is a `tmpfs` mount point, and each existing entry in it is a bind
  mount point, so none of them can be renamed. Also, a missing target cannot
  be bind-mounted at all. Only a private parent stops a run from creating it
  on the host.
- New files cannot be added to a directory that a glob `Include` reads, for
  example `~/.ssh/config.d`.
- You cannot edit the global `~/.claude/CLAUDE.md` or `~/.codex/AGENTS.md`,
  or add or change user-level skills, agents or commands (`~/.claude/skills`,
  `~/.claude/agents`, `~/.claude/commands`). User-level `/memory` edits and
  `/agents` changes at user level fail. Project files (`./CLAUDE.md`,
  `.claude/agents`) and `~/.claude/projects/*/memory` stay writable.
- You cannot edit a hook script, status line script or MCP server program
  that the user-level config names by an absolute or `~` path. Other files
  next to it stay writable. **On Linux, every directory between HOME and the
  program becomes a private skeleton**, as for a git target above. For
  example, an MCP server `command` of `~/.nvm/versions/node/v22/bin/npx` makes
  `~/.nvm`, `~/.nvm/versions`, `~/.nvm/versions/node`,
  `~/.nvm/versions/node/v22` and `~/.nvm/versions/node/v22/bin` skeletons, so
  new top-level entries that `nvm install` or `npm i -g` write in a run (a new
  Node version, a new global package link) are lost when the run ends. The
  reason is the "Why every directory between HOME and the target" item above.
- On macOS, a missing `~/.codex` cannot be created in a run (as for
  `~/.claude`): run `codex` once outside the sandbox first. On Linux,
  `~/.codex` is not a skeleton (`LINUX_PARENT_BIND` in `bin/agent-aws`): it is
  bound read-write, and only its existing `AGENTS.md` and `AGENTS.override.md`
  are bound read-only on top. So Codex can replace `config.toml` by rename and
  create new files there. This is safe against the rename attack because
  `~/.codex` and each existing instruction file are mount points (`EBUSY`).
  The cost: on Linux, a missing `~/.codex/AGENTS.md` or
  `~/.codex/AGENTS.override.md` can be created in a run and stays on the host
  (macOS denies it). If a config target is a missing direct child of
  `~/.codex`, or is below a direct child that is missing or a symlink (for
  example a `notify` program in a missing `~/.codex/bin`), `~/.codex` stays a
  skeleton, so a missing program there cannot be created. If that direct
  child is an existing real directory (the Codex install in
  `~/.codex/packages`, or an existing `~/.codex/bin`), `~/.codex` stays a
  read-write bind and only that child becomes a private skeleton (a mount
  point, so it cannot be renamed). **The parent bind is used only when
  no protected child is a symlink.** If `~/.codex/AGENTS.md` or
  `AGENTS.override.md` is a symlink (existing or dangling, for example into a
  dotfiles repo with GNU stow), `~/.codex` stays a skeleton on Linux and the
  skeleton costs apply again: new top-level entries in `~/.codex` are lost
  when the run ends, and a rename-replace of `config.toml` fails (`EBUSY`);
  in-place writes to `config.toml` still work. The reason: in a read-write
  bind, the read-only mount destination would be the host symlink, so the run
  would fail to start, or `rm` plus a new file would persist on the host.
  This was not tested with the real
  Codex ([#8](https://github.com/juanheyns/agent-aws/issues/8)).
- The run's own command is read-only in a run
  ([#13](https://github.com/juanheyns/agent-aws/issues/13)): **auto-update
  of `claude` or `codex` inside a run fails** (it writes a new version to
  `~/.local/share/claude/versions` or `~/.codex/packages/standalone` and
  repoints the link). Update them outside the sandbox. On macOS a new
  `releases/<version>` directory can still be created next to the protected
  one, but `current` cannot be repointed. `npm i -g`, `pip install` or
  `brew upgrade` of the run's command in a run also fail when they write into
  its install prefix.
- **On Linux, every directory between HOME and the run's command or a
  protected PATH chain link becomes a private skeleton**, as for a git target
  above: for `claude`, `~/.local/share` (new top-level entries in it are lost
  when the run ends; existing entries cannot be renamed); for `codex`,
  `~/.codex/packages`, `~/.codex/packages/standalone` and
  `~/.codex/packages/standalone/releases` (`~/.codex` itself stays a
  read-write bind, see above). The note at run start lists them for the run's
  command; it does not list the skeletons of an `aws`/`python3` chain link
  (for example `~/d` for `~/d/link`). On Linux a protected directory link is
  mounted read-only from its target, so its target directory is read-only in
  the run too (on macOS only the link is protected).
- You cannot edit fish `config.fish`, `conf.d`, `functions` or `completions`;
  `fisher install`/`update` and `funcsave` fail. `set -U` works on both
  platforms: on Linux, `~/.config/fish` is bound read-write (like `~/.codex`)
  and only the existing protected entries are bound read-only on top, so fish
  can replace `fish_variables` by rename. The Linux cost: a missing
  `config.fish`, `conf.d`, `functions` or `completions` can be created in a run
  and stays on the host (macOS denies it). I guess that fish creates `conf.d`,
  `functions` and `completions` at its first start, so they normally exist;
  this was not verified. The same applies to `~/.oh-my-zsh` and its `custom`
  directory. **The parent bind is used only when no protected child is a
  symlink** (as for `~/.codex` above). If `config.fish`, `conf.d`,
  `functions` or `completions` is a symlink (existing or dangling, for
  example into a dotfiles repo with GNU stow), `~/.config/fish` stays a
  private skeleton on Linux and the skeleton costs apply again: **`set -U` is
  not saved on Linux** (fish replaces `fish_variables` by rename, which fails
  over the bind mount), and new top-level entries in `~/.config/fish` are lost
  when the run ends. If `~/.oh-my-zsh/custom` is a symlink, `~/.oh-my-zsh`
  stays a skeleton on Linux: `omz update` can fail when it replaces or removes
  a top-level file of the checkout, and new top-level entries are lost.
- `npm login`, `npm adduser`, `npm logout` and `npm config set`/`delete` fail
  (they write `~/.npmrc`). Use a project `.npmrc` or run them outside the
  sandbox.
- You cannot add or edit oh-my-zsh custom plugins and themes, or edit
  `~/.zpreztorc`, `~/.inputrc`, `~/.config/starship.toml`, direnv config, tmux
  config, `~/.vimrc`, `~/.vim/vimrc`, `~/.config/vim/vimrc`, nvim `init.lua`/`init.vim`, IPython startup scripts or
  the `$PYTHONSTARTUP` file.
- On macOS, a missing `~/.config/fish`, `~/.oh-my-zsh`, `~/.vim`,
  `~/.config/vim`, `~/.config/tmux`, `~/.config/nvim` or
  `~/.ipython/profile_default` cannot be created in a run (they are ancestors
  of protected paths). So installing oh-my-zsh, a first fish start or a first
  IPython start in a run fails or cannot save its state; do it once outside
  the sandbox. On Linux, `~/.vim`, `~/.config/vim`, `~/.config/tmux`,
  `~/.config/nvim` and `~/.ipython/profile_default` are private skeletons:
  existing entries stay writable, but new top-level entries (for example a
  `~/.vim/pack` directory that a plugin manager creates in a run) disappear
  when the run ends.
- oh-my-zsh auto-update (`omz update`, a `git pull`) works in a run on both
  platforms (on Linux only when `~/.oh-my-zsh/custom` is not a symlink, see
  above) while upstream does not change the files that it tracks in
  `custom/` (`example.zsh`, `plugins/example`, `themes/example`). If it does,
  the update fails, because `custom` is read-only.

### Not protected

The [#4 assessment](https://github.com/juanheyns/agent-aws/pull/5) confirmed
with disposable fixtures that a run can still write these. Each one is tracked:

| Class | Example that stays writable | Issue |
|---|---|---|
| Install targets of PATH executables that are not the run's command, commands started through a wrapper, interpreters of script commands | the `codex` install when you run `claude`; `sh -c 'claude'`, `env X=1 claude`, `npx`; the `node` and `node_modules` of a Node CLI | [#24](https://github.com/juanheyns/agent-aws/issues/24) (the run's own command is protected since [#13](https://github.com/juanheyns/agent-aws/issues/13); see [the run's own command](#the-runs-own-command)) |
| Git/SSH commands that are shell strings, and config that agent-aws does not parse | `!sh -c '…'` aliases, `ProxyCommand sh -c …`, a relative `core.hooksPath`, system git config, `/etc/ssh/ssh_config`, ssh `${VAR}` paths | [#6](https://github.com/juanheyns/agent-aws/issues/6) (decision: not resolvable in general; see [git and SSH config targets](#git-and-ssh-config-targets)) |
| Repository-local configuration | `.git/config` (`core.fsmonitor`), `.git/hooks`, project `.claude/settings.json`, `.envrc` | [#7](https://github.com/juanheyns/agent-aws/issues/7) |
| Agent config that the agent writes itself | `~/.claude.json` itself (a new `mcpServers` entry), `~/.claude/plugins/**`, `~/.codex/config.toml` itself (a new `mcp_servers` or `notify`), files that `~/.claude/CLAUDE.md` imports with `@path`, interpreter-prefixed hook commands, other agents (not surveyed); project config is [#7](https://github.com/juanheyns/agent-aws/issues/7) | [#8](https://github.com/juanheyns/agent-aws/issues/8) (needs a test with the real agents; see [agent instructions and config programs](#agent-instructions-and-config-programs)) |
| Code sourced by startup files, other shells, tool config, other bin dirs | files that rc files source (`~/.zsh/*.zsh`, dotfile repositories), oh-my-zsh core files, `~/.zprezto`, zsh plugin managers, fish `fish_variables` and the user vendor directories `~/.local/share/fish/vendor_conf.d`, `vendor_functions.d` and `vendor_completions.d`, nushell/xonsh, editor and tool init that is not in the list, `~/bin` and `~/go/bin` not in PATH | [#9](https://github.com/juanheyns/agent-aws/issues/9) (decision: protect a short list; the rest needs the strong boundary, [#14](https://github.com/juanheyns/agent-aws/issues/14); see [shell and tool startup code](#shell-and-tool-startup-code)) |
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
