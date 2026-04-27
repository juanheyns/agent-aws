# Roadmap

Items are roughly in priority order. Open an issue if you want to push
something up the list or volunteer to take it on.

## Long-running broker daemon

Today, `agent-aws run` mints STS credentials at launch and writes them to
the sandbox's tempdir. Those creds expire after the role's max session
duration (1h default for IDC permission sets). When they expire, the agent
gets `ExpiredToken` errors and the developer re-runs `agent-aws run`.

A small broker daemon outside the sandbox could refresh creds in place via
`credential_process`:

- Daemon holds the SSO token; lives as long as the agent session.
- A tiny `credential_process` binary inside the sandbox forwards requests
  to the daemon over a Unix socket bind-mounted into the sandbox.
- Refresh is automatic and invisible to the agent.

This is the biggest UX improvement on the table.

## Tighter sandbox profiles

Both backends currently start permissive and deny credential locations.
Switching to *deny by default + explicit allows* would also let us:

- Restrict `process-exec` to an allowlist of binaries.
- Block outbound connections to anything other than `*.amazonaws.com`.
- Require explicit opt-in for write access to the working tree.

Worth the complexity once the basics are solid.

## SCP / permission-boundary template

A Service Control Policy template that denies destructive actions for any
session tagged `agent=true`, plus changes to `agent-aws run` to inject that
session tag via `sts:AssumeRole` instead of using the raw IDC role creds.

This is the AWS-side backstop: even if the entire sandbox were bypassed,
the credentials themselves cannot perform writes.

## `agent-gh` and beyond

The shim/sandbox/cred-broker pattern generalises beyond AWS. Likely next
target: a `gh` shim that scopes a GitHub PAT down to specific repos and
read-only operations.

## Brew formula polish

- `bottle :unneeded` annotations once we're stable.
- Tests in the formula beyond `--help`.
- Optional: a separate `agent-aws@dev` formula tracking `main`.
