# Getting started

## Install

=== "macOS"

    ```sh
    brew install juanheyns/tap/agent-aws
    ```

    `sandbox-exec` is built into macOS — no further setup needed.

=== "Linux (Homebrew)"

    ```sh
    brew install juanheyns/tap/agent-aws
    ```

    Linux additionally needs `bubblewrap`. Install via your distro:

    ```sh
    sudo apt install bubblewrap     # Debian / Ubuntu
    sudo dnf install bubblewrap     # Fedora / RHEL
    sudo pacman -S bubblewrap       # Arch
    ```

    Unprivileged user namespaces must be enabled (default on Ubuntu 22.04+,
    Fedora, Arch). On hardened distros:

    ```sh
    sudo sysctl kernel.unprivileged_userns_clone=1
    ```

=== "From source"

    ```sh
    git clone https://github.com/juanheyns/agent-aws.git
    cd agent-aws
    ln -s "$PWD/bin/agent-aws" /usr/local/bin/agent-aws
    ```

## First run

```sh
# 1. Tell agent-aws which profiles in ~/.aws/config it should expose
agent-aws init --all

# 2. Log into your IAM Identity Center session (opens a browser)
agent-aws login

# 3. Confirm the sandboxed identity is read-only
agent-aws whoami
# {
#   "Arn": "arn:aws:sts::...:assumed-role/AWSReservedSSO_ReadOnlyAccess_.../you"
# }

# 4. Run an agent with scoped AWS access
agent-aws run -- claude
```

Inside the sandboxed process:

- `aws ...` works with the default profile.
- `aws --profile NAME ...` switches between configured accounts.
- `~/.aws/` is empty / unreadable. The agent cannot mint admin credentials
  even if it tries.

## What `agent-aws init` does

1. Reads `~/.aws/config`.
2. Filters out any profile whose `sso_role_name` looks admin-equivalent
   (`Administrator*`, `PowerUser*`, `*FullAccess`).
3. Prompts you to pick which of the remaining profiles to expose. (Or pass
   `--all`, or `--profile NAME` repeatedly.)
4. Writes `~/.agent-aws/config.json` (mode `600`) with the selected profiles
   and their SSO session metadata.

The init step never touches credentials — it only records *which* profiles
the agent is allowed to use. Real STS credentials are minted at run time.

## Common workflows

### Scope a run to a single account

```sh
agent-aws run --profile ProdReadOnly -- claude
```

The tempdir handed to the sandbox contains creds for `ProdReadOnly` only.
Other profiles are entirely absent.

### Sanity-check an account quickly

```sh
agent-aws whoami --profile DevReadOnly
```

### See configured profiles and SSO freshness

```sh
agent-aws status

# Config:  /Users/you/.agent-aws/config.json
# Default: DevReadOnly
#
#   profile        account         role            sso
#   -------------  --------------  --------------  -------
# * DevReadOnly    111111111111    ReadOnlyAccess  ok
#   ProdReadOnly   222222222222    ReadOnlyAccess  ok
```
