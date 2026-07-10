---
description: Manage nthpartyfinder's subprocessor URL cache (list / show / clear / validate).
argument-hint: "list | show <domain> | clear <domain>|--all | validate"
allowed-tools: "Bash(nthpartyfinder *)"
---

Wrap `nthpartyfinder cache` with the action in `$ARGUMENTS`:

- `list` → `nthpartyfinder cache list`
- `show <domain>` → `nthpartyfinder cache show <domain>`
- `clear <domain>` → `nthpartyfinder cache clear <domain>`
- `clear --all` → `nthpartyfinder cache clear --all` — **destructive; confirm with the user first**
- `validate` → `nthpartyfinder cache validate` (add `--detailed` for per-URL results)

Never run `cache clear --all` without explicit user confirmation. Report the command's output back to the user.
