# Security policy

PacWardX installs a root helper (`packaging/pacwardx-priv`) and a sudoers rule, so its own security matters.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. Include steps to reproduce and the affected version.

## In scope

- Any way to make `pacwardx-priv` do more than its fixed, read-only subcommands, or to influence it from an unprivileged context.
- The installer creating files or permissions that are broader than documented.
- The daemon socket accepting commands from other users.
- Secret values (tokens, passwords) leaking into state files, reports, logs or the UI.

## Out of scope

- Missing checks or false positives. Please open a normal issue for those.
