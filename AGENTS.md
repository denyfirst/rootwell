# Working on Rootwell

Read `docs/ENGINEERING.md`, `docs/PRODUCT-PLAN.md`, `docs/STATUS.md` and
`docs/SECURITY-INVARIANTS.md` before changing code.

Rootwell is exclusively self-hosted. Security comes before convenience, and a
person who knows little about certificates must still understand every page.
Security changes need observable success, refusal, malformed-input and
relevant abuse tests. Sabotage both directions and demonstrate that the
intended tests fail, then restore and rerun the gates. Test pages against the
real daemon, not only stand-ins: `docs/CONTAINER-RECOVERY.md` installs it.

Everything in this repository is in English: code, pages, documents, commit
messages and pull requests. Use plain words on pages; state a limit once,
where it matters.

Use a purpose-specific branch (`topic/rootwell-<purpose>-<YYYY-MM-DD>`),
inspect the index, stage explicit paths, and sign every commit with the
configured Denyfirst commit identity. Follow the PR, self-review and release
gates in `docs/ENGINEERING.md`, and merge with a merge commit. Never use
`git add -A`, squash, rebase, auto-merge, or an administrative bypass.

Porch and Keybash are read-only references. Do not edit their files,
worktrees, Git configuration, index, branches, tags, remotes or releases. Make
Rootwell changes only within this repository. Private signing keys and
production credentials must never be copied into this repository, logs, tests
or CI.
