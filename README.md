# claude-git-guard

A [Claude Code](https://claude.com/claude-code) PreToolUse hook that blocks multi-agent branch accidents.

One Node file, no dependencies. Catches the specific failure modes that surface when you run several Claude Code agents on the same git repo — edits on protected branches, cross-session branch drift, cross-repo `cd`, `git pull` pointer moves, and more.

Derived from a hook that's been in production for three months inside a personal AI system. 

## What it blocks

| Rule | Path | Behaviour | What it prevents |
|---|---|---|---|
| **R0** | Bash | Block | `cd <different-repo>` — prevents subsequent git commands operating on the wrong repo. Moving between the repo's own worktrees is allowed. |
| **R1** | Edit/Write | Block | Edits on a protected branch (default: `main`, `master`) |
| **R1b** | Edit/Write | Block | Edits to **tracked** files when other sessions are on the same (non-worktree) checkout — forces worktrees. New untracked and gitignored files are allowed. |
| **R2** | Edit/Write | Block | Edits after another session switched branches underneath you |
| **R3** | Bash | Warn | `git push` targeting a protected branch |
| **R4** | Bash | Warn | When other sessions are active: destructive verbs (`stash`, `checkout`, `switch`, `reset --hard`) and commands that sweep up their files (`add -A`/`-u`/`.`, `commit -a`/`.`, `clean`, `stash -u`) |
| **R5** | Bash | Block | `git pull <remote> <wrong-ref>` — the silent pointer-move that can cost commits of drift |

Blocks emit `[git-guard R<n> BLOCKED]` on stderr with a recovery message. Warnings emit JSON with `permissionDecision: "allow"` so the warning text reaches Claude without blocking the tool call.

**The Edit/Write rules (R1, R1b, R2) see only Claude Code's Edit and Write tools.** A file written from the shell (`cp`, `mv`, `cat > file`, `sed -i`, `tee`, a script) is invisible to them. The Bash rules inspect git commands, not shell writes.

## Install

1. Copy `git-guard.mjs` into your project (suggested location: `.claude/hooks/git-guard.mjs`), or clone this repo once and point each project's hook at the clone by absolute path (`node /path/to/claude-git-guard/git-guard.mjs`) so every project runs the same copy.

2. Register it in `.claude/settings.json` (project-wide) or `.claude/settings.local.json` (machine-specific, typically gitignored):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Edit|Write|Bash",
           "hooks": [
             {
               "type": "command",
               "command": "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/git-guard.mjs\""
             }
           ]
         }
       ]
     }
   }
   ```

3. Restart Claude Code.

To verify: try to `Edit` any file while on `main`. You should see R1 block with the full message on stderr.

## Configuration

All config via environment variables. Set at Claude Code launch time, or in your shell profile.

| Env var | Default | Purpose |
|---|---|---|
| `GIT_GUARD_PROTECTED_BRANCHES` | `main,master` | Comma list of branches to hard-block edits on (R1) and warn on pushes to (R3). |
| `GIT_GUARD_STATE_DIR` | `${os.tmpdir()}/claude-git-guard` | Where session state files live. Each session writes one JSON per worktree here. |
| `GIT_GUARD_ALLOW_POINTER_MOVE` | (unset) | Prefix this on a single command to bypass R5 once: `GIT_GUARD_ALLOW_POINTER_MOVE=1 git pull origin some-other-branch`. |

To disable the hook, remove its entry from `settings.json` — there is deliberately no runtime kill switch. An env-var toggle can be leaned on in ways that defeat the guard; removing the registration is the honest escape.

## How it works

**Worktree-aware branch resolution.** The hook resolves the branch from the file being edited, not from its own CWD. Each worktree tracks its branch independently. Session state is keyed by `{session_id}-{md5(worktree).slice(0,8)}`.

**Session state.** On first Edit/Write, the hook records the session's branch for that worktree in the state dir. On subsequent edits, it compares — if they differ (another session switched branches underneath), it blocks with R2. `git branch -m` renames are detected and tolerated.

**Shared checkouts (R1b).** When another session's state file names the same non-worktree checkout, the hook asks git whether the file being edited is in the index (`git ls-files`, committed or staged). Only tracked files are blocked: those are what another session's stash, reset, checkout or commit will clobber or sweep up. A new draft or a gitignored scratch file is untouched by all of those, so it is allowed. The path is canonicalized first, so a symlink to a tracked file, or a case-variant name on macOS, still counts as tracked. The commands that *do* catch untracked files are covered by R4 instead.

**Same repo, by common git dir (R0).** Every worktree has its own toplevel but shares the repo's common git dir, so R0 compares common dirs. `cd` between the main checkout and its worktrees is allowed; `cd` into a different repo is blocked.

**Fail-open by default.** Parse errors, missing git context, unreadable state files — the hook exits 0 and allows the tool call. Two exceptions fail CLOSED: R5, on branch-lookup failure while a pull command is detected, because a silent pointer-move is precisely what R5 exists to prevent; and R1b, when another session is active and the trackedness check errors, because it can't prove the file is safe to edit.

**Warnings via JSON output.** R3 and R4 do not block; they emit a stdout JSON payload that Claude Code surfaces to the agent as decision context. Older Claude Code versions that only honor plain stdout will not see these warnings — the hard blocks (R0, R1, R1b, R2, R5) use stderr + exit 2 and work on all versions.

## Security notes

- All git calls use `execFileSync` with argv (no shell). A crafted `file_path` containing shell metacharacters cannot break out.
- Stdin JSON is parsed inside a try/catch; invalid input fails open.
- Oversize commands (>100 KB) skip regex work and fail open.
- State files are not trusted — corrupt JSON in the state dir is skipped silently.

## Known limitations

- **Developed and tested on macOS and Linux.** POSIX paths assumed. Windows contributors welcome.
- **`GIT_GUARD_PROTECTED_BRANCHES` is a literal list**, not a glob. If you use `release/*` style branches, list them explicitly.
- **Shell writes bypass R1/R1b/R2.** See above: only the Edit and Write tools are inspected.
- **R4 is a warning, and string-level.** It parses `git` invocations (including `-C <path>`, `--work-tree=`, `--git-dir=`), not aliases, shell functions or dynamically built commands. It counts every other active session, including ones on other repos.
- **Edit/Write into a directory that doesn't exist yet fails open** for all Edit/Write rules, because the branch is resolved from the file's directory.
- **R1b is bypass-able via worktrees**, which is the point — the worktree IS the fix, not a workaround.

## Testing

```bash
npm test
```

The harness spawns the hook as a subprocess with controlled stdin, asserts exit codes and stdout/stderr contents. Add a case for any new rule or edge case.

## Changelog

**0.2.0**
- R1b blocks only edits to files git tracks (committed or staged). New untracked and gitignored files are allowed on a shared checkout. Fails closed if the check errors.
- R4 also warns on commands that sweep up other sessions' files: `git add -A`/`--all`/`-u`/`.`, `git commit -a`/`.`, `git clean` (not dry runs), `git stash -u`/`--include-untracked`/`--all`. All matches in a chained command are named. `git reset -q --hard` (flag not first) is now caught.
- R0 decides "different repo" by the common git dir, so `cd` into the repo's own worktrees is no longer blocked. Paths are canonicalized with native realpath, so case-variant spellings on macOS read as the same repo.
- Docs: the Edit/Write rules do not see shell writes; corrected the stale claim that `git -C <path> pull` is out of R5's scope.

**0.1.0** — initial release.

## Maintenance

This is a personal project released as-is. I built it for my own multi-agent Claude Code workflow. Issues and PRs are welcome, but I'll only act on them when something affects me. Fork freely — you're probably faster fixing a problem in your own fork than waiting on me.

Any change to the rules themselves should come with at least one test.

## Credits

Written by JD Deitch as part of Pilot, a personal AI operating system. The hook was born from running multiple Claude Code agents against the same repo and watching them step on each other.

## License

MIT. See [LICENSE](./LICENSE).
