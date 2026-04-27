# Configuration

## `~/.agent-aws/config.json`

Mode `0600`, owned by the developer. Schema:

```json
{
  "default_profile": "DevReadOnly",
  "profiles": {
    "DevReadOnly": {
      "sso_session": "Acme",
      "sso_start_url": "https://acme.awsapps.com/start/#/",
      "sso_region": "us-east-1",
      "account_id": "111111111111",
      "role_name": "ReadOnlyAccess",
      "default_region": "us-east-1"
    },
    "ProdReadOnly": {
      "sso_session": "Acme",
      "sso_start_url": "https://acme.awsapps.com/start/#/",
      "sso_region": "us-east-1",
      "account_id": "222222222222",
      "role_name": "ReadOnlyAccess",
      "default_region": "us-east-1"
    }
  }
}
```

| Field | Notes |
|---|---|
| `default_profile` | Name of the profile written as `[default]` in the sandbox's credentials file. |
| `profiles` | Map of profile name → configuration. Profile names are exactly what the agent uses with `aws --profile NAME`. |
| `profiles.*.role_name` | Hardcoded at init time. Init refuses any name matching `*admin*`, `*poweruser*`, or `*fullaccess*`. |
| `profiles.*.account_id` | The AWS account the role is in. |
| `profiles.*.sso_session` / `sso_start_url` / `sso_region` | Inherited from the source `[sso-session ...]` block in `~/.aws/config`. |

The file is rewritten by every `agent-aws init`. Manual edits survive only
until the next init.

## Subcommands

### `agent-aws init`

Bootstrap or rewrite `~/.agent-aws/config.json` from `~/.aws/config`.

| Flag | Description |
|---|---|
| `--profile NAME` | Source profile to include. Repeatable. |
| `--all` | Include every non-admin profile in `~/.aws/config`. |
| `--default NAME` | Mark this profile as the default. Defaults to first selected. |

With no flags, `init` prompts interactively.

Admin-equivalent profiles are filtered out automatically — they can't be
selected even by name.

### `agent-aws login`

Wraps `aws sso login` for every distinct `sso_session` in your config.

| Flag | Description |
|---|---|
| `--session NAME` | Log in to a specific `sso-session` only. |

### `agent-aws status`

Print configured profiles, the default, and per-session SSO freshness.

### `agent-aws run -- <cmd...>`

Mint short-lived STS credentials and launch `<cmd>` in the sandbox.

| Flag | Description |
|---|---|
| `--profile NAME` | Restrict this run to a single profile. Other profiles are *absent*, not just non-default. |

### `agent-aws whoami`

Convenience for `agent-aws run -- aws sts get-caller-identity`. Accepts
`--profile NAME`.

## Inside the sandbox

The wrapped process sees a clean environment with these AWS-relevant vars
set:

| Variable | Value |
|---|---|
| `AWS_CONFIG_FILE` | Path to the per-run config in the tempdir. |
| `AWS_SHARED_CREDENTIALS_FILE` | Path to the per-run credentials in the tempdir. |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Default profile's region. |
| `AGENT_AWS_ACTIVE` | `1` — useful for shell prompts or tooling to detect the sandbox. |
| `AGENT_AWS_PROFILES` | Comma-separated list of the active profile names. |
| `AGENT_AWS_DEFAULT_PROFILE` | The profile being used as `[default]`. |

## Custom read-only roles

AWS's managed `ReadOnlyAccess` policy includes data-plane actions
(`s3:Get*`, `dynamodb:GetItem`, etc.). For sensitive accounts, define a
custom IAM permission set restricted to control-plane reads, give it to
your developers via Identity Center, and reference it by name:

```sh
agent-aws init --role MyControlPlaneReadOnly
```

The init safety check rejects names containing `admin`, `poweruser`, or
`fullaccess`, so any unusual but non-admin name is accepted.
