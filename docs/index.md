# agent-aws

Run CLI agents against AWS in a scoped **read-only** sandbox — even when the
developer running the agent has both Administrator and ReadOnly roles
assigned via IAM Identity Center.

## Why

Modern coding agents need access to real infrastructure to be useful, but
giving them the same blast radius as their human operator is a recipe for
trouble. Prompt injection or a bad call from the agent shouldn't be able to
cause damage your team can't easily undo.

`agent-aws` solves this with a layered design:

1. The agent gets short-lived STS credentials for a non-admin role only.
2. The credentials live in a per-run tempdir; the developer's `~/.aws/` —
   including the SSO token cache that could be used to mint admin
   credentials — is invisible to the sandboxed process.
3. AWS-side IAM rejects any write actions even if the sandbox were bypassed.

## Quick taste

```sh
brew install juanheyns/tap/agent-aws

agent-aws init --all          # pick read-only profiles from ~/.aws/config
agent-aws login               # standard SSO browser flow
agent-aws run -- claude       # agent now has read-only AWS access
```

## What's next

- **[Getting started →](getting-started.md)** install, init, login, first run.
- **[Threat model →](threat-model.md)** what attacks this stops, and what it
  doesn't.
- **[Configuration →](configuration.md)** multi-profile, `~/.agent-aws/config.json`
  schema, all CLI flags.
- **[Platform support →](platform-support.md)** macOS `sandbox-exec` vs Linux
  `bwrap` (bubblewrap), and the differences between them.
