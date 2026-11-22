# Working on Rootwell

Read [`docs/ENGINEERING.md`](docs/ENGINEERING.md),
[`docs/PRODUCT-PLAN.md`](docs/PRODUCT-PLAN.md),
[`docs/STATUS.md`](docs/STATUS.md) and the relevant security documents before
changing code.

Security is the first requirement. A change is not complete when it merely
works; it must carry evidence for success, refusal, malformed input, and
relevant abuse cases. Deliberately sabotage new behavior in both directions and
confirm the intended tests fail.

Everything in this repository is in English: code, pages, documents, commit
messages and pull requests. Use plain words on pages; state a limit once,
where it matters.

Use a purpose-specific branch (`topic/rootwell-<purpose>-<YYYY-MM-DD>`), stage
explicit paths, sign every commit, and wait for all required checks. Follow the
solo-maintainer review and release audit gates in `docs/ENGINEERING.md`, then
merge with a merge commit. Never use `git add -A`, squash, rebase, auto-merge,
or an administrative bypass.

Rootwell, Porch and Keybash are separate products. Do not edit, stage, commit,
or change configuration in the Porch or Keybash repositories while working on
Rootwell; read them only.
