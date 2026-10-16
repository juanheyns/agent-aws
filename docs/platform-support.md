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
`~/.config/autostart`, and the resolved installation directory are denied.
Generated rules protect conventional paths, resolved targets, and every
ancestor against rename. Launch PATH directories, launcher paths, and the
Python/AWS CLI installation prefixes are protected too.
Other runs' files are unreadable and unwritable; limited pathname metadata
is allowed so shell globs report denied files rather than silently skipping them.
`open`, `osascript`, `launchctl`, mounts, and the Launch Services / quarantine
Mach services named in the sandbox profile are denied.

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

Existing shell startup files, `~/.config/brnr`, `~/Library/LaunchAgents`, and
the installation directory are mounted read-only. A private directory skeleton
for HOME and the parents of protected paths prevents a missing protected path
from being created persistently on the host. Linux also protects systemd user
units and autostart entries. Existing ordinary children (such as project
directories) are bound read-write. **New entries in these
skeleton directories disappear when the run ends**; create new projects inside
an existing writable directory. Symlink targets of protected startup files are
also read-only, including targets reached through symlinked ancestors. Launch
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
All launch-PATH directories are read-only: self-updates and global package
installs into those directories must run outside the sandbox. Empty or `.`
PATH entries also protect the current directory and produce a warning; use
absolute entries to avoid making a working directory read-only.
