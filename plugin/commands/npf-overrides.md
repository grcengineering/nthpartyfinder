---
description: Inspect or revert nthpartyfinder local domain→org overrides (the store that wins every lookup).
argument-hint: "[list | revert <domain>] [--source claude_verified]"
allowed-tools: "Bash(nthpartyfinder *)"
---

Manage the local vendor override store via the nthpartyfinder `review` subcommands, based on `$ARGUMENTS`:

- **list** (default when no action given): run `nthpartyfinder review list`. Append `--source claude_verified` to show only Claude-verified entries. Show where the store lives with `nthpartyfinder review path`.
- **revert `<domain>`**: run `nthpartyfinder review revert <domain>` to remove an override (undo an accepted mapping). Confirm the exact domain with the user before removing.

Always print the resulting override list so the user sees the effect. Each row is `domain  organization  [source]  added`; `[claude_verified]` marks a mapping saved by the review skill.
