# Platform support

`agent-aws` is a single Python script (`bin/agent-aws`) that dispatches to
a platform-native sandbox backend. Cred minting, env handling, and lifecycle
are identical across platforms; only the sandbox argv differs.

| Platform | Sandbox backend | Required tool |
|---|---|---|
| macOS 12+ | `sandbox-exec` + `share/agent-aws/agent-aws.sb` | built-in |
| Linux | `bwrap` (bubblewrap) | distro package manager |

## macOS

Uses `sandbox-exec` with the profile at `share/agent-aws/agent-aws.sb`. The
profile is permissive by default and explicitly denies reads and writes on
`~/.aws/` and `~/.agent-aws/`:

```scheme
(version 1)
(allow default)
(deny file-read* file-write*
  (subpath (param "HOME_AWS_DIR"))
  (subpath (param "AGENT_DIR")))
```

Reads and writes return `Operation not permitted` (`EPERM`). Writes to shell
startup files (`.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `.zlogout`,
`.bashrc`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.profile`),
`~/Library/LaunchAgents`, `~/.config/brnr`, `~/.config/systemd/user`,
`~/.config/autostart`, git and SSH configuration (`~/.gitconfig`,
`~/.config/git`, `~/.ssh/config`, `~/.ssh/rc`, `~/.ssh/authorized_keys`,
`~/.ssh/authorized_keys2`), the files and programs that this git and SSH
configuration refers to (include targets, `core.hooksPath`, helper programs;
see [git and SSH config targets](threat-model.md#git-and-ssh-config-targets)),
Claude Code settings (`~/.claude/settings.json`,
`~/.claude/settings.local.json`), user-level agent instructions
(`~/.claude/CLAUDE.md`, `agents`, `commands`, `skills`, `~/.codex/AGENTS.md`,
`AGENTS.override.md`) and the programs that the agent config names (hooks, MCP
servers, Codex `notify`; see
[agent instructions and config programs](threat-model.md#agent-instructions-and-config-programs)),
other shells' and tools' startup code (fish `config.fish`, `conf.d`,
`functions`, `completions`, `~/.oh-my-zsh/custom`, `~/.npmrc` and others; see
[shell and tool startup code](threat-model.md#shell-and-tool-startup-code)),
and the resolved installation directory are
denied. Generated rules protect conventional paths, resolved targets, and every
ancestor against rename. Launch PATH directories, launcher paths, the
Python/AWS CLI installation prefixes (including the interpreter and venv of
a Python `aws` script; other `aws` wrappers are not followed, see
[#12](https://github.com/juanheyns/agent-aws/issues/12)), and Homebrew
prefixes except `var/` are protected too. If the `aws` or `python3` prefix
is HOME or an ancestor of HOME, only the executable's directory is protected.
Other runs' files are unreadable and unwritable; limited pathname metadata
is allowed so shell globs report denied files rather than silently skipping them.
`open`, `osascript`, `launchctl`, mounts, and the Launch Services / quarantine
Mach services named in the sandbox profile are denied.

Because ancestors of protected paths are denied as literals (against
rename-in), **a missing `~/.ssh`, `~/.claude` or `~/.codex` cannot be created
inside a run**. On a fresh account, the first `ssh` (which creates
`~/.ssh/known_hosts`), the first `claude` (which creates `~/.claude/projects`)
or the first `codex` fails in the sandbox. Run `ssh`, `claude` and `codex`
once outside the sandbox first. After that,
`known_hosts` and `~/.claude/projects` stay writable. The same applies to
`~/.config/fish`, `~/.oh-my-zsh`, `~/.vim`, `~/.config/vim`, `~/.config/tmux`,
`~/.config/nvim` and `~/.ipython/profile_default`: install oh-my-zsh and start fish and IPython
once outside the sandbox.

`sandbox-exec` is technically deprecated by Apple but has shown no signs of
removal in years; Apple uses it themselves for App Sandbox. If it ever does
go away, the migration target is likely `seatbelt` or whatever replaces it
at the framework level.

## Linux

Uses `bwrap` (bubblewrap) — a single-binary sandbox primitive used by
Flatpak, Steam's runtime, and various other isolation tools. Install via
distro:

```sh
sudo apt install bubblewrap     # Debian / Ubuntu
sudo dnf install bubblewrap     # Fedora / RHEL
sudo pacman -S bubblewrap       # Arch
```

System directories are mounted read-only. `/tmp` is private, with only the
current run's credentials mounted back in. `~/.aws` and `~/.agent-aws` are
hidden behind empty, read-only mounts. PID, IPC and UTS namespaces are private.
Networking is still shared; the egress lock is a separate future step.

Existing shell startup files, `~/.config/brnr`, `~/Library/LaunchAgents`, git
and SSH configuration and the files and programs that it refers to, Claude
Code settings, user-level agent instructions and the programs that the agent
config names, the shell and tool startup code, and the installation directory are mounted read-only. A private directory skeleton
for HOME and the parents of protected paths prevents a missing protected path
from being created persistently on the host. Linux also protects systemd user
units and autostart entries. Existing ordinary children (such as project
directories) are bound read-write. **New entries in these
skeleton directories disappear when the run ends**; create new projects inside
an existing writable directory. `~/.ssh` and `~/.claude` are skeletons too:
existing `known_hosts` and `~/.claude/projects` stay writable, but a new
top-level entry there (for example a first `known_hosts`) is private to the
run. The same applies to **every directory between HOME and a git or SSH
config target or a program that the agent config names**, also when the
target is missing. For example, when
`~/.gitconfig` includes `~/Source/github.com/me/dotfiles/git-extra`, a
`git clone` into `~/Source/github.com/<new-owner>/` is lost when the run ends,
and `[includeIf "gitdir:~/work/"]` with `path = ~/work/.gitconfig` makes
`~/work` a skeleton. An MCP server `command` of
`~/.nvm/versions/node/v22/bin/npx` makes `~/.nvm`, `~/.nvm/versions`, …,
`~/.nvm/versions/node/v22/bin` skeletons, so new top-level entries from
`nvm install` or `npm i -g` in a run are lost. `~/.codex` is not a skeleton:
it is bound read-write and only its existing `AGENTS.md` and
`AGENTS.override.md` are bound read-only, so a missing one can be created in a
run on Linux (macOS denies it). If one of these instruction files is a
symlink (for example into a dotfiles repo), `~/.codex` stays a skeleton: new
top-level entries in it are lost when the run ends, and a rename-replace of
`config.toml` fails. `~/.config/fish` and `~/.oh-my-zsh` are bound
the same way: `fish_variables` and the oh-my-zsh checkout are plain files in a
read-write bind, so `set -U` and `omz update` can replace them by rename. Only
the existing `config.fish`, `conf.d`, `functions`, `completions` and
`~/.oh-my-zsh/custom` are bound read-only; a missing one can be created in a run
on Linux (macOS denies it). As for `~/.codex`, this parent bind is used only
when no protected child is a symlink: if `config.fish`, `conf.d`, `functions`,
`completions` or `~/.oh-my-zsh/custom` is a symlink (for example into a
dotfiles repo), that directory stays a skeleton on Linux, so **`set -U` is not
saved** (fish replaces `fish_variables` by rename) and `omz update` can fail on
top-level files of the checkout. An existing top-level entry in a skeleton directory is a
bind mount: it cannot be replaced by rename or unlinked. At run start,
agent-aws prints the skeleton directories that come from git, SSH and agent config
targets and from the `$PYTHONSTARTUP` file.
The reason is in the
[threat model](threat-model.md#what-normal-use-now-breaks-inside-a-run).
Symlink targets of protected startup files are also read-only, including targets reached through symlinked ancestors. Launch
PATH directories and executable installation paths are protected too. This avoids the missing-file hole in `--ro-bind-try`.

### Unprivileged user namespaces

`bwrap` uses Linux user namespaces, which must be enabled. They are by
default on:

- Ubuntu 22.04+
- Fedora (any recent version)
- Arch
- Debian 12+

On hardened or container-restricted distros you may need:

```sh
sudo sysctl kernel.unprivileged_userns_clone=1
```

If `bwrap` fails with `setting up uid map: ... Permission denied`, this is
the cause.

## Asymmetries

| Property | macOS | Linux |
|---|---|---|
| File denial | Path returns `EPERM` | Path appears empty |
| PID namespace | Shared with host | Agent is PID 1 in its own namespace |
| IPC | Shared | Isolated |
| `ps` of host processes | Possible | Blocked |
| Network | Shared | Shared |

The Linux backend gives stronger process isolation (PID/IPC/UTS unshares)
than `sandbox-exec` provides. macOS uses filesystem and selected process/Mach restrictions.

## Adding a new backend

If you want to add a third backend (e.g. macOS `container`, or systemd-run
on Linux), the integration point is `build_sandbox_argv()` in
`bin/agent-aws`. Add a new `build_sandbox_argv_<platform>()` function
returning an argv list, plus a presence check in `check_sandbox_tool()`,
and dispatch from `build_sandbox_argv()`.

The cred-minting code path is platform-agnostic and won't need to change.

Launchers use Python isolated mode (`-I`), and the interpreter's user
site-packages directory is write-protected to prevent `.pth` startup injection.
Installation-site directories reported by `site.getsitepackages()` are also
protected, even outside the interpreter prefix and through symlink targets:
`-I` still executes `.pth` files from those directories.
All launch-PATH directories and Homebrew prefixes (except `var/`) are
read-only: self-updates, `brew install`, and global package installs into those
directories must run outside the sandbox. Changes to protected git, SSH and
Claude Code settings also fail inside a run, and so do changes to included git
config files, `core.hooksPath` scripts and helper programs that the git or SSH
config names. If `git` is not in PATH or cannot read the config, the run
continues with a warning, and those targets are not protected. Empty or `.`
PATH entries also protect the current directory and produce a warning; use
absolute entries to avoid making a working directory read-only.

These protections cover a list of known paths, not the whole host. See the
[supported host-isolation boundary](threat-model.md#supported-host-isolation-boundary)
for what is not protected.
