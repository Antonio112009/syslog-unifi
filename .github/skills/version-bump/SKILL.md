---
name: version-bump
description: "Automatically bump package.json version before git commit and push. Use when: committing changes, pushing code, git commit, git push, deploying. Decides semver level (major, minor, patch) based on the nature of staged changes."
---

# Version Bump

Automatically bump the `version` field in `package.json` before committing and pushing.

## When to Activate

This skill applies whenever the agent is about to run `git commit` and/or `git push`. Before executing the commit, perform the version bump procedure below.

## Procedure

### 1. Determine the change scope

Review the staged changes (or the changes being committed) and classify them:

- **major** — breaking changes: removed or renamed public APIs, changed database schema in incompatible ways, removed features, changed configuration format
- **minor** — new features: added endpoints, new UI components, new configuration options, added database columns with defaults (backward-compatible)
- **patch** — everything else: bug fixes, performance improvements, refactors, documentation updates, dependency bumps, style changes, typo fixes

When in doubt, default to **patch**.

### 2. Bump the version

1. Read the current `version` from [package.json](../../../package.json)
2. Parse as `major.minor.patch`
3. Increment the determined part (major resets minor+patch to 0, minor resets patch to 0)
4. Update the `version` field in `package.json`

### 3. Include in the commit

Stage the updated `package.json` alongside the other changes. The commit message should reflect the actual changes — do not make the commit solely about the version bump. Append the new version to the commit message, e.g.:

```
feat: add protocol filter to dashboard (v0.2.0)
```

or for multiple changes:

```
fix: resolve SSE reconnection, refactor log parser (v0.1.1)
```

### 4. Push

Proceed with `git push` as requested.
