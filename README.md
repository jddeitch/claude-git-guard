# claude-git-guard

A [Claude Code](https://claude.com/claude-code) PreToolUse hook that blocks multi-agent branch accidents.

One Node file, no dependencies. Catches the specific failure modes that surface when you run several Claude Code agents on the same git repo — edits on protected branches, cross-session branch drift, cross-repo `cd`, `git pull` pointer moves, and more.

Derived from a hook that's been in production for three months inside a personal AI system. See [the accompanying essay](https://jddeitch.substack.com/) for the backstory (link goes live with the repo).

## What it blocks

| Rule | Path | Behaviour | What it prevents |
|---|---|---|---|
| **R0** | Bash | Block | `cd <different-repo>` — prevents subsequent git commands operating on the wrong repo |
| **R1** | Edit/Write | Block | Edits on a protected branch (default: `main`, `master`) |
| **R1b** | Edit/Write | Block | Edits when other sessions are on the same checkout — forces worktrees |
| **R2** | Edit/Write | Block | Edits after another session switched branches underneath you |
| **R3** | Bash | Warn | `git push` targeting a protected branch |
| **R4** | Bash | Warn | Destructive verbs (`stash`, `checkout`, `switch`, `reset --hard`) when other sessions are active |
| **R5** | Bash | Block | `git pull <remote> <wrong-ref>` — the silent pointer-move that can cost commits of drift |

Blocks emit `[git-guard R<n> BLOCKED]` on stderr with a recovery message. Warnings emit JSON with `permissionDecision: "allow"` so the warning text reaches Claude without blocking the tool call.

## Install

1. Copy `git-guard.mjs` into your project. Suggested location: `.claude/hooks/git-guard.mjs`.

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

**Fail-open by default.** Parse errors, missing git context, unreadable state files — the hook exits 0 and allows the tool call. The exception is R5: on branch-lookup failure while a pull command is detected, it fails CLOSED, because a silent pointer-move is precisely what R5 exists to prevent.

**Warnings via JSON output.** R3 and R4 do not block; they emit a stdout JSON payload that Claude Code surfaces to the agent as decision context. Older Claude Code versions that only honor plain stdout will not see these warnings — the hard blocks (R0, R1, R1b, R2, R5) use stderr + exit 2 and work on all versions.

## Security notes

- All git calls use `execFileSync` with argv (no shell). A crafted `file_path` containing shell metacharacters cannot break out.
- Stdin JSON is parsed inside a try/catch; invalid input fails open.
- Oversize commands (>100 KB) skip regex work and fail open.
- State files are not trusted — corrupt JSON in the state dir is skipped silently.

## Known limitations

- **Developed and tested on macOS and Linux.** POSIX paths assumed. Windows contributors welcome.
- **`GIT_GUARD_PROTECTED_BRANCHES` is a literal list**, not a glob. If you use `release/*` style branches, list them explicitly.
- **`git -C <path> pull …`** is out of R5's scope. Pulls with `-C` fall through because R5 checks the hook's CWD branch, not the `-C` target's.
- **R1b is bypass-able via worktrees**, which is the point — the worktree IS the fix, not a workaround.

## Testing

```bash
npm test
```

The harness spawns the hook as a subprocess with controlled stdin, asserts exit codes and stdout/stderr contents. Add a case for any new rule or edge case.

## Contributing

Issues and PRs welcome. Any change that touches the rules themselves should come with at least one test.

## Credits

Written by JD Deitch as part of Pilot, a personal AI operating system. The hook was born from running multiple Claude Code agents against the same repo and watching them step on each other.

## License

MIT. See [LICENSE](./LICENSE).
