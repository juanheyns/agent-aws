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
profile is permissive by default and explicitly denies `file-read*` on
`~/.aws/` and `~/.agent-aws/`:

```scheme
(version 1)
(allow default)
(deny file-read*
  (subpath (param "HOME_AWS_DIR"))
  (subpath (param "AGENT_DIR")))
```

Reads return `Operation not permitted` (`EPERM`).

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

The argv built by `agent-aws run`:

```sh
bwrap \
  --ro-bind /usr /usr \
  --ro-bind /etc /etc \
  --ro-bind-try /bin /bin \
  --ro-bind-try /sbin /sbin \
  --ro-bind-try /lib /lib \
  --ro-bind-try /lib64 /lib64 \
  --ro-bind-try /opt /opt \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --bind <creds_dir> <creds_dir> \
  --bind $HOME $HOME \
  --tmpfs $HOME/.aws \
  --tmpfs $HOME/.agent-aws \
  --die-with-parent \
  --unshare-pid --unshare-ipc --unshare-uts \
  --new-session \
  -- <cmd...>
```

Reads of `~/.aws/` return *empty directory* — the tmpfs overlay hides the
real contents entirely.

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
than `sandbox-exec` provides. macOS users get filesystem isolation only.

## Adding a new backend

If you want to add a third backend (e.g. macOS `container`, or systemd-run
on Linux), the integration point is `build_sandbox_argv()` in
`bin/agent-aws`. Add a new `build_sandbox_argv_<platform>()` function
returning an argv list, plus a presence check in `check_sandbox_tool()`,
and dispatch from `build_sandbox_argv()`.

The cred-minting code path is platform-agnostic and won't need to change.
