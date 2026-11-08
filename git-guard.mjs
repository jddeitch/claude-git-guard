#!/usr/bin/env node

// claude-git-guard — Claude Code PreToolUse hook for multi-agent safety.
//
// https://github.com/jddeitch/claude-git-guard
//
// Edit|Write path — Hard gates:
//   R1   Block edits on a protected branch
//   R1b  Block edits to TRACKED files on a shared (non-worktree) checkout
//        while other sessions are active on it. Untracked and gitignored
//        files are allowed. Fails closed if trackedness can't be checked.
//   R2   Block if branch drifted since session start
//
// Bash path — mixed:
//   R0   BLOCK cd/pushd to a different git repo — every cd in the command,
//        ~ included (by common git dir, so cd into
//        the repo's own worktrees is allowed)
//   R3   WARN before `git push` targeting a protected branch
//   R5   BLOCK `git pull <remote> <ref>` on ANY branch when ref differs
//        from the current branch name. Override via
//        GIT_GUARD_ALLOW_POINTER_MOVE=1 prefix.
//   R4   WARN when other sessions work where the command reaches (same
//        checkout; same repo for the shared stash list) on destructive verbs
//        (stash, checkout, switch, reset --hard) and on commands that
//        sweep up other sessions' files (add -A/-u/., commit -a/., clean,
//        stash -u)
//
// The Edit|Write rules see ONLY the Edit and Write tools. Files written from
// the shell (`cp`, `mv`, `cat > f`, `sed -i`, `tee`, a script) are invisible
// to R1/R1b/R2 — the Bash path inspects git commands, not shell writes.
//
// R3/R4/R5 are worktree-aware for `git -C <path> <verb>` and the equivalent
// `--git-dir=<path>`, `--work-tree=<path>` global-option forms: the branch
// used for comparison is the branch checked out at <path>, not the hook's
// own CWD. Without this, a `git -C <path> push main` would bypass R3
// entirely — the global-option placement is the 5th documented bypass class.
//
// Every block writes `[git-guard R<n> BLOCKED]` on stderr so orchestrators
// can branch on the specific rule, not just on "something blocked". Warnings
// emit as stdout JSON (hookSpecificOutput.permissionDecision: "allow" +
// permissionDecisionReason) so they reach Claude's context without blocking.
//
// WORKTREE-AWARE: The hook resolves the branch from the file being edited,
// not from the hook's own CWD. Each worktree tracks its branch independently.
// Session state keyed by {session_id}-{worktree_hash} in the state dir.
//
// Fail-open by default on parse errors. R5 fails CLOSED on branch-lookup
// failure when a pull command is detected — can't prove we're safe, so block.
//
// Config (env vars):
//   GIT_GUARD_PROTECTED_BRANCHES  comma list, default "main,master"
//   GIT_GUARD_STATE_DIR           default: os.tmpdir()/claude-git-guard
//   GIT_GUARD_ALLOW_POINTER_MOVE  "1" in the command line to bypass R5 once
//
// TESTABLE: pipe a PreToolUse JSON payload on stdin. exit 2 = block, 0 = allow.
//   echo '{"tool_name":"Bash","tool_input":{"command":"git pull origin foo"},"session_id":"t"}' \
//     | node git-guard.mjs
//   echo "exit=$?"

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

const DEFAULT_PROTECTED_BRANCHES = ['main', 'master'];
const PROTECTED_BRANCHES = (() => {
  const raw = process.env.GIT_GUARD_PROTECTED_BRANCHES;
  if (!raw) return DEFAULT_PROTECTED_BRANCHES;
  const parsed = raw.split(',').map(s => s.trim()).filter(Boolean);
  return parsed.length > 0 ? parsed : DEFAULT_PROTECTED_BRANCHES;
})();

const STATE_DIR = process.env.GIT_GUARD_STATE_DIR
  || path.join(os.tmpdir(), 'claude-git-guard');

const STALE_MS = 24 * 60 * 60 * 1000;
const MAX_COMMAND_BYTES = 100_000;

// R5 override env var. Parsed from the command string (not process.env)
// because the hook runs BEFORE Bash executes, so shell assignments in the
// command haven't reached process.env yet.
const POINTER_GUARD_OVERRIDE_ENV = 'GIT_GUARD_ALLOW_POINTER_MOVE';

/**
 * Resolve the git toplevel and current branch for a given file path.
 * Worktree-aware: a file inside a worktree returns that worktree's branch,
 * not the main working tree's branch.
 *
 * Uses execFileSync (argv, no shell) to avoid shell-interpolation of
 * attacker-controlled path segments — a file_path containing a `"` could
 * otherwise break out of the quoted argument in a shell command string.
 */
function resolveGitContext(filePath) {
  // Nearest EXISTING ancestor: a Write may create new directories, and
  // `git -C <missing dir>` fails — which used to fail the whole hook open,
  // so a Write to main/newdir/x.md slipped past R1 entirely.
  const dir = filePath ? nearestExistingDir(path.dirname(path.resolve(filePath))) : process.cwd();
  const toplevel = execFileSync('git', ['-C', dir, 'rev-parse', '--show-toplevel'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
  const branch = execFileSync('git', ['-C', toplevel, 'rev-parse', '--abbrev-ref', 'HEAD'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
  return { toplevel, branch };
}

/** Walk up from `dir` to the first path that exists as a directory. */
function nearestExistingDir(dir) {
  let cur = dir;
  for (;;) {
    try {
      if (fs.statSync(cur).isDirectory()) return cur;
    } catch {
      // missing — keep walking up
    }
    const parent = path.dirname(cur);
    if (parent === cur) return cur;
    cur = parent;
  }
}

/**
 * Canonicalize a path that may not exist yet: canonicalize its nearest
 * existing ancestor (symlinks, on-disk case) and re-append the missing tail.
 * `/var/…/repo/new/x.md` → `/private/var/…/repo/new/x.md` on macOS.
 */
function canonicalizeMaybeMissing(p) {
  const abs = path.resolve(p);
  const base = nearestExistingDir(abs);
  return path.join(canonicalPath(base), path.relative(base, abs));
}

// Within-invocation memo for the hook CWD's branch. R3's bare-push check and
// R5 can both call getCurrentBranch on the same invocation.
let _cachedBranch = null;

function getCurrentBranch() {
  if (_cachedBranch !== null) return _cachedBranch;
  _cachedBranch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
  return _cachedBranch;
}

function worktreeHash(toplevel) {
  return crypto.createHash('md5').update(toplevel).digest('hex').slice(0, 8);
}

function sessionKey(sessionId, toplevel) {
  return `${sessionId}-${worktreeHash(toplevel)}`;
}

function ensureStateDir() {
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  }
}

function cleanStaleFiles() {
  try {
    const now = Date.now();
    for (const file of fs.readdirSync(STATE_DIR)) {
      const fp = path.join(STATE_DIR, file);
      const stat = fs.statSync(fp);
      if (now - stat.mtimeMs > STALE_MS) {
        fs.unlinkSync(fp);
      }
    }
  } catch {
    // Non-fatal — stale files just cause extra warnings
  }
}

function readSessionState(key) {
  try {
    const fp = path.join(STATE_DIR, `${key}.json`);
    const raw = fs.readFileSync(fp, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// `untrackedOnly`: true while every Edit/Write this session has made on this
// checkout was PROVEN to target an untracked/ignored file. R1b ignores such
// sessions (a draft-writer must not lock the main session out of tracked
// files); R4 still counts them (their drafts are what add -A/clean sweep).
// State files without the field (older versions) read as false.
function writeSessionState(key, branch, sessionId, toplevel, untrackedOnly) {
  try {
    const fp = path.join(STATE_DIR, `${key}.json`);
    fs.writeFileSync(fp, JSON.stringify({
      branch,
      session_id: sessionId,
      toplevel,
      untracked_only: untrackedOnly === true,
      recorded_at: Date.now(),
    }));
  } catch {
    // Non-fatal
  }
}

function getOtherSessions(currentSessionId) {
  try {
    const now = Date.now();
    const sessions = [];
    for (const file of fs.readdirSync(STATE_DIR)) {
      if (!file.endsWith('.json')) continue;
      const fp = path.join(STATE_DIR, file);
      try {
        const raw = fs.readFileSync(fp, 'utf-8');
        const data = JSON.parse(raw);
        if (data.session_id !== currentSessionId && (now - data.recorded_at) < STALE_MS) {
          sessions.push(data);
        }
      } catch {
        // Skip corrupt files
      }
    }
    return sessions;
  } catch {
    return [];
  }
}

/**
 * Emit a warning that reaches Claude via the documented JSON output path.
 * stdout JSON with permissionDecision "allow" + reason surfaces the reason
 * text to Claude as decision context, without blocking the tool call.
 */
function emitWarning(reason) {
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'allow',
      permissionDecisionReason: reason,
    },
  };
  process.stdout.write(JSON.stringify(output));
}

function firstLine(err) {
  const text = String(err?.stderr || err?.message || err).trim();
  return text.split('\n')[0];
}

/**
 * Is `filePath` known to git's index in the checkout at `toplevel`?
 * Returns true/false; THROWS if it can't tell (R1b treats that as tracked).
 *
 * "Tracked" means present in the index — committed files and staged new
 * files alike, since both are what stash/reset/checkout act on. Untracked
 * and gitignored files are not in the index and return false (a
 * force-added ignored file IS in the index and returns true).
 *
 * The path is canonicalized first (symlinks and on-disk case). Without
 * that, on macOS an Edit of `readme.md` would modify the tracked
 * `README.md` while `ls-files readme.md` reports it untracked. A path that
 * doesn't exist yet (possibly in directories that don't exist yet) keeps
 * its name and canonicalizes its nearest existing ancestor.
 *
 * `--literal-pathspecs` stops `*`, `?`, `[` in a file name being read as a
 * glob that matches other, tracked files. The pathspec is absolute, so git
 * itself errors (→ fail closed) if it still resolves outside this checkout.
 */
function isTrackedPath(toplevel, filePath) {
  if (!filePath) throw new Error('no file path in tool input');
  const abs = path.resolve(filePath);
  const top = canonicalPath(toplevel);
  // The path itself, with only its directory canonicalized (keeps a
  // symlink's own name; used when the file doesn't exist yet).
  const lexical = path.join(canonicalizeMaybeMissing(path.dirname(abs)), path.basename(abs));
  let canonical;
  try {
    canonical = fs.realpathSync.native(abs);
  } catch {
    canonical = lexical;
  }
  // A symlink in this checkout pointing OUTSIDE it: the target is in no
  // index of ours, so ask about the link itself (tracked link → blocked)
  // rather than hand git an out-of-repo path it would refuse.
  if (canonical !== top && !canonical.startsWith(top + path.sep)) {
    canonical = lexical;
  }
  const out = execFileSync(
    'git',
    ['-C', top, '--literal-pathspecs', 'ls-files', '-z', '--', canonical],
    { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  return out.length > 0;
}

function handleEditWrite(sessionId, filePath) {
  const { toplevel, branch } = resolveGitContext(filePath);
  const key = sessionKey(sessionId, toplevel);

  // R1: Block edits on a protected branch
  if (PROTECTED_BRANCHES.includes(branch)) {
    process.stderr.write(
      `[git-guard R1 BLOCKED] Cannot edit files on "${branch}" — configured as a protected branch.\n\n` +
      'DO NOT STEAMROLL GIT-GUARD!\n' +
      'Use your agent\'s worktree tool, or `git worktree add -b feat/<name> .worktrees/<name>`.\n' +
      'Do NOT just create a branch in place — that shifts every other agent on this checkout to your branch.\n' +
      'Do NOT delete state files or work around this. It protects other running sessions.\n' +
      `(Configure protected branches via GIT_GUARD_PROTECTED_BRANCHES. Default: ${DEFAULT_PROTECTED_BRANCHES.join(',')}.)\n`
    );
    process.exit(2);
  }

  ensureStateDir();
  cleanStaleFiles();

  // R1b: Block shared-checkout edits. Solo sessions on the main tree are fine.
  const isWorktree = (() => {
    try {
      // In a worktree, .git is a file (not a directory) containing "gitdir: ..."
      const dotGit = path.join(toplevel, '.git');
      return fs.statSync(dotGit).isFile();
    } catch {
      return false;
    }
  })();

  // Only TRACKED files are blocked: those are what another session's stash,
  // reset, checkout or commit will clobber or sweep up. A new untracked or
  // gitignored file (a draft, a scratch note) isn't touched by any of those,
  // so blocking it only forces a worktree for no safety gain. The commands
  // that DO sweep untracked files (add -A, clean, stash -u) are R4's job.
  //
  // Trackedness is checked on every shared-checkout edit, even with no one
  // else around, so the session's state records whether it has only ever
  // touched untracked files. Only sessions that have edited tracked files
  // count as "others" here — otherwise a session that wrote one draft would
  // lock the session doing the real work out of its own tracked files.
  let provenUntracked = false;
  if (!isWorktree) {
    // Fail CLOSED: if trackedness can't be established, treat as tracked.
    let tracked = true;
    let checkError = null;
    try {
      tracked = isTrackedPath(toplevel, filePath);
    } catch (e) {
      checkError = e;
    }
    provenUntracked = !tracked;

    const othersOnSameToplevel = getOtherSessions(sessionId)
      .filter(s => s.toplevel === toplevel && s.untracked_only !== true);
    if (othersOnSameToplevel.length > 0) {
      if (tracked) {
        const sessionList = othersOnSameToplevel
          .map(s => `  - session ${s.session_id.slice(0, 8)}... on branch "${s.branch}"`)
          .join('\n');
        const reason = checkError
          ? `Could not determine whether ${filePath ?? '(no file path)'} is tracked by git — failing closed.\n` +
            `  ${firstLine(checkError)}\n`
          : `${filePath} is tracked by git.\n`;
        process.stderr.write(
          `[git-guard R1b BLOCKED] ${reason}` +
          `${othersOnSameToplevel.length} other session(s) active on this checkout:\n` +
          `${sessionList}\n\n` +
          'DO NOT STEAMROLL GIT-GUARD!\n' +
          'Edits to tracked files on a shared checkout collide: another session\'s stash, reset,\n' +
          'checkout or commit will sweep up or clobber your change (and yours will theirs).\n' +
          'New untracked or gitignored files are allowed here; tracked files need a worktree.\n' +
          'Use your agent\'s worktree tool, or `git worktree add -b feat/<name> .worktrees/<name>`.\n' +
          'Do NOT just create a branch in place — that moves every session listed above onto your branch.\n' +
          'Do NOT delete state files or work around this.\n'
        );
        process.exit(2);
      }
    }
  }

  // R2: Branch drift detection
  const state = readSessionState(key);

  // The marker only ever goes true → false: one tracked (or unprovable)
  // edit makes this session a tracked-file editor for R1b from then on.
  const untrackedOnly = provenUntracked && (!state || state.untracked_only === true);

  if (!state) {
    writeSessionState(key, branch, sessionId, toplevel, untrackedOnly);
    process.exit(0);
  }

  if (state.branch === branch) {
    // Rewrite on every allowed edit: refreshes recorded_at (sessions expire
    // STALE_MS after their LAST edit, not their first — a session running
    // longer than a day used to drop out of R1b/R4 while still editing) and
    // clears the untracked-only mark once a tracked file is touched.
    writeSessionState(key, branch, sessionId, toplevel, untrackedOnly);
    process.exit(0);
  }

  // `git branch -m` deletes the old ref — if it's gone, rename, not drift.
  try {
    execFileSync('git', ['-C', toplevel, 'rev-parse', '--verify', `refs/heads/${state.branch}`], {
      encoding: 'utf-8', timeout: 5000, stdio: 'pipe',
    });
  } catch {
    writeSessionState(key, branch, sessionId, toplevel, untrackedOnly);
    process.exit(0);
  }

  const staleFile = path.join(STATE_DIR, `${key}.json`);
  process.stderr.write(
    `[git-guard R2 BLOCKED] Branch changed from "${state.branch}" to "${branch}" since this session started. ` +
    'Another session may have switched branches underneath you.\n\n' +
    'DO NOT STEAMROLL GIT-GUARD!\n' +
    'TO RECOVER:\n' +
    `1. Clear ONLY your session file: rm ${staleFile}\n` +
    `2. Do NOT delete other files in ${STATE_DIR} — they protect other active sessions.\n` +
    '3. Confirm with the human before proceeding — do not just work around this.\n'
  );
  process.exit(2);
}

/**
 * Extract EVERY `cd`/`pushd` at a command boundary (start, `&&`, `||`, `;`,
 * newline), in order. Each entry is { raw, target } where target is the
 * statically-resolvable path (`~` and `~/…` expanded; bare `cd` = home) or
 * null when it can't be known (`$VAR`, backticks, `cd -`, `~user`).
 * `(cd x && …)` subshells are deliberately not matched: they don't move the
 * session's working directory.
 */
function extractCdTargets(command) {
  const re = /(?:^|&&|;|\|\||\n)[ \t]*(?:cd|pushd)(?:[ \t]+(?:"([^"]*)"|'([^']*)'|([^\s;&|()]+))|(?=[ \t]*(?:$|&&|;|\|\||\n)))/g;
  const out = [];
  let m;
  while ((m = re.exec(command)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; }
    const raw = m[1] ?? m[2] ?? m[3];
    const quoted = m[3] === undefined && raw !== undefined; // shell doesn't expand ~ in quotes
    let target;
    if (raw === undefined) target = os.homedir();
    else if (raw.includes('`') || (raw.includes('$') && m[2] === undefined) || raw === '-') target = null;
    else if (quoted) target = raw;
    else if (raw === '~') target = os.homedir();
    else if (raw.startsWith('~/')) target = path.join(os.homedir(), raw.slice(2));
    else if (raw.startsWith('~')) target = null;
    else target = raw;
    out.push({ raw: raw ?? '', target });
  }
  return out;
}

/**
 * Canonicalize a path: resolve symlinks and, on case-insensitive filesystems
 * (macOS default), the on-disk case. Uses the native realpath(3) — Node's JS
 * `fs.realpathSync` resolves symlinks but keeps the caller's case, so
 * `~/projects/app` and `~/Projects/app` would read as two paths.
 * Returns the input unchanged if it can't be resolved (e.g. doesn't exist).
 */
function canonicalPath(p) {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/**
 * Resolve the canonical common git dir for a working dir. Sibling worktrees
 * of one repo share this dir even though their toplevels differ. Throws if
 * `cwd` is not inside a git repo.
 */
function resolveCommonGitDir(cwd) {
  const out = execFileSync('git', ['-C', cwd, 'rev-parse', '--git-common-dir'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
  return canonicalPath(path.isAbsolute(out) ? out : path.resolve(cwd, out));
}

/**
 * Best-effort toplevel for a working dir — for human-readable messages only.
 */
function safeToplevel(cwd) {
  try {
    return execFileSync('git', ['-C', cwd, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8', timeout: 5000,
    }).trim();
  } catch {
    return '(unknown)';
  }
}

/**
 * Check if a cd target would leave the current git repo.
 * Returns { blocked: true, message } if it would, { blocked: false } otherwise.
 *
 * "Different repo" is decided by the COMMON git dir, not the worktree
 * toplevel: `cd` into the repo's own `.worktrees/<branch>` (or any sibling
 * worktree) shares the common git dir and is safe, so it must not be blocked.
 * Only a move into a genuinely separate repo is the escape R0 exists to catch
 * — there, later git commands would silently operate on the wrong project.
 */
function checkCdEscape(cds) {
  if (cds.length === 0) return { blocked: false };

  let currentCommon;
  try {
    currentCommon = resolveCommonGitDir(process.cwd());
  } catch {
    return { blocked: false }; // hook CWD not in a git repo — nothing to escape from
  }

  // Walk the cds in order: a relative target resolves against the previous
  // one (`cd a && cd ../other`). After an unresolvable cd, relative targets
  // can't be placed, but absolute ones still can.
  let running = process.cwd();
  for (const { raw, target } of cds) {
    if (target === null) { running = null; continue; }
    let absTarget;
    if (path.isAbsolute(target)) absTarget = target;
    else if (running !== null) absTarget = path.resolve(running, target);
    else continue;
    running = absTarget;

    try {
      if (!fs.statSync(absTarget).isDirectory()) continue;
    } catch {
      continue; // doesn't exist (yet) — let Bash report it
    }

    // execFileSync (argv, no shell) so a cd target containing shell
    // metacharacters can't break out.
    let targetCommon;
    try {
      targetCommon = resolveCommonGitDir(absTarget);
    } catch {
      continue; // target not in a git repo — cd there can't retarget git
    }
    if (currentCommon === targetCommon) continue;

    return {
      blocked: true,
      message: escapeMessage(raw || '~', absTarget),
    };
  }
  return { blocked: false };
}

function escapeMessage(cdTarget, absTarget) {
  return (
    `[git-guard R0 BLOCKED] "cd ${cdTarget}" would move to a different git repo.\n` +
    `  Current repo: ${safeToplevel(process.cwd())}\n` +
    `  Target repo:  ${safeToplevel(absTarget)}\n\n` +
    'DO NOT STEAMROLL GIT-GUARD!\n' +
    'This will cause all subsequent git commands to operate on the wrong repo.\n' +
    'Use absolute paths instead of cd, or run commands in a separate worktree.\n'
  );
}

/**
 * Parse leading `KEY=VAL` shell assignments. Returns { envs, rest }.
 *
 * Needed because the hook sees the command string BEFORE Bash runs it, so
 * `GIT_GUARD_ALLOW_POINTER_MOVE=1 git …` isn't visible via process.env.
 * Accepts both upper- and lower-case names — POSIX shells allow either,
 * and constraining to uppercase would create a bypass (e.g. `foo=bar git …`
 * left the prefix un-consumed, defeating an anchored `^git`).
 */
function parseLeadingEnvVars(command) {
  const envs = {};
  let rest = command.trimStart();
  const pattern = /^([A-Za-z_][A-Za-z0-9_]*)=(\S+)\s+/;
  for (let i = 0; i < 50; i++) {
    const m = rest.match(pattern);
    if (!m) break;
    envs[m[1]] = m[2];
    rest = rest.slice(m[0].length);
  }
  return { envs, rest };
}

/**
 * Read a single shell token starting at `pos`. Handles double-quoted,
 * single-quoted, and unquoted forms. Unquoted tokens terminate at whitespace
 * or shell-boundary characters. Returns [value, nextPos].
 */
/**
 * Index of the quote closing the one at `pos`, or -1 if unterminated.
 * Inside double quotes a backslash escapes the next char (`"say \"hi\""`);
 * single quotes have no escapes, as in POSIX sh.
 */
function closingQuote(command, pos) {
  const q = command[pos];
  for (let i = pos + 1; i < command.length; i++) {
    if (q === '"' && command[i] === '\\') { i++; continue; }
    if (command[i] === q) return i;
  }
  return -1;
}

function readShellToken(command, pos) {
  if (pos >= command.length) return [null, pos];
  const first = command[pos];
  if (first === '"' || first === "'") {
    const start = pos + 1;
    const endIdx = closingQuote(command, pos);
    if (endIdx === -1) return [null, command.length];
    return [command.slice(start, endIdx), endIdx + 1];
  }
  const start = pos;
  while (pos < command.length && !/[\s;&|()`]/.test(command[pos])) pos++;
  return [command.slice(start, pos), pos];
}

// Defensive cap on invocations parsed per command. A 100KB command full of
// `git ` tokens would otherwise be O(n²) in this walker. Real commands have
// at most 2-3 invocations (chained pull/push/status patterns).
const MAX_INVOCATIONS_PER_COMMAND = 50;

/**
 * Extract every `git` invocation from the command string, with global
 * options parsed out. Returns an array of { cPath, subcommand, rest } —
 * one entry per `git` token, including each side of chained commands
 * (`git -C a pull; git -C b push`).
 *
 *   cPath        value of `-C <path>` (or --work-tree/--git-dir equivalent),
 *                null if none. Used by R3/R5 to resolve the branch of the
 *                targeted worktree rather than the hook's CWD.
 *   subcommand   push, pull, stash, reset, checkout, etc.
 *   rest         args after the subcommand, up to the next shell boundary.
 *
 * Out of scope (falls through):
 *   - Dynamically-constructed invocations via command substitution, shell
 *     functions, aliases, or variable expansion in the subcommand position.
 *     These are resolution-layer bypasses that no string-level inspection
 *     can close.
 *   - Embedded literal `git` tokens inside quoted arguments (`echo "git
 *     pull origin foo"`). Accepted as safe false positives — the user can
 *     invoke the override env var.
 */
function extractGitInvocations(command) {
  const invocations = [];
  const gitRe = /\bgit\b/g;
  let gm;
  while ((gm = gitRe.exec(command)) !== null) {
    if (invocations.length >= MAX_INVOCATIONS_PER_COMMAND) break;
    let pos = gm.index + 3;
    let cPath = null;

    while (pos < command.length) {
      while (pos < command.length && /[ \t]/.test(command[pos])) pos++;
      if (pos >= command.length) break;

      // -C <path>
      if (command[pos] === '-' && command[pos + 1] === 'C' && /[ \t]/.test(command[pos + 2] || '')) {
        pos += 2;
        while (pos < command.length && /[ \t]/.test(command[pos])) pos++;
        const [value, nextPos] = readShellToken(command, pos);
        if (cPath === null && value) cPath = value;
        pos = nextPos;
        continue;
      }
      // -c <key=val>
      if (command[pos] === '-' && command[pos + 1] === 'c' && /[ \t]/.test(command[pos + 2] || '')) {
        pos += 2;
        while (pos < command.length && /[ \t]/.test(command[pos])) pos++;
        const [, nextPos] = readShellToken(command, pos);
        pos = nextPos;
        continue;
      }
      // --git-dir=<path>, --work-tree=<path>
      const longOptMatch = command.slice(pos).match(/^--(git-dir|work-tree)=/);
      if (longOptMatch) {
        const optName = longOptMatch[1];
        pos += longOptMatch[0].length;
        const [value, nextPos] = readShellToken(command, pos);
        if (cPath === null && value) {
          // --work-tree=<dir>: dir is the worktree root — same shape as -C.
          // --git-dir=<dir>:   dir is the .git folder; walk up one level to
          //                    reach the worktree root. Heuristic, but covers
          //                    the common bypass shape.
          cPath = optName === 'git-dir' ? path.dirname(value) : value;
        }
        pos = nextPos;
        continue;
      }
      // Other global options (--bare, --no-*, --exec-path=, etc.) — consume
      // the token without affecting cPath. If it starts with '-' treat it as
      // an option; otherwise it's the subcommand and we stop.
      if (command[pos] === '-') {
        const [, nextPos] = readShellToken(command, pos);
        pos = nextPos;
        continue;
      }
      break;
    }

    if (pos >= command.length) continue;

    const subStart = pos;
    while (pos < command.length && /[a-zA-Z-]/.test(command[pos])) pos++;
    const subcommand = command.slice(subStart, pos);
    if (!subcommand) continue;

    // Scan to the next shell boundary OUTSIDE quotes, so a quoted
    // `-m "feat(x): y; z"` doesn't end the invocation and hide later flags.
    const restStart = pos;
    while (pos < command.length && !/[;&|()`]/.test(command[pos])) {
      if (command[pos] === '"' || command[pos] === "'") {
        const end = closingQuote(command, pos);
        pos = end === -1 ? command.length : end + 1;
        continue;
      }
      pos++;
    }
    const rest = command.slice(restStart, pos).trim();

    invocations.push({ cPath, subcommand, rest });
  }
  return invocations;
}

/**
 * Parse the args string for a git-pull invocation (everything after the
 * 'pull' subcommand). Returns { remote, src, dst } when we see
 * `<remote> <src>[:<dst>]`, null otherwise.
 *
 * Intentional null returns (fall through, allow):
 *   bare `git pull`                → uses configured upstream — no pointer risk
 *   `git pull <remote>` (no ref)   → same
 *   `git pull --rebase` (no args)  → same
 *
 * Why src separate from dst: the refspec form `git pull origin foo:main`
 * updates local `main` to origin's `foo` via fetch-refspec AND then merges
 * FETCH_HEAD (which is foo) into HEAD. R5 inspects SRC, not DST — the source
 * is what lands on the current branch through the merge step.
 */
function matchPullArgs(rest) {
  const pattern = /^(?:(?:--[\w-]+(?:=\S+)?|-[a-zA-Z]+)\s+)*([\w.@:/-]+)\s+([\w./+-]+)(?::([\w./+-]+))?(?:\s|$)/;
  const m = rest.match(pattern);
  if (!m) return null;
  return { remote: m[1], src: m[2], dst: m[3] };
}

/**
 * Resolve the branch for a git invocation. If cPath is set, look up the
 * branch of that worktree; otherwise use the hook's own CWD. Returns the
 * branch name or throws if it can't be determined.
 */
function resolveBranchForInvocation(cPath) {
  if (!cPath) return getCurrentBranch();
  const abs = path.isAbsolute(cPath) ? cPath : path.resolve(process.cwd(), cPath);
  // Defense in depth: a path starting with `-` would be misinterpreted by
  // git as an option flag. path.resolve() prepends CWD for relative inputs
  // so this shouldn't fire — but refuse rather than hand git an attacker-
  // shaped argv.
  if (abs.startsWith('-')) throw new Error(`git-guard: refusing cPath with leading dash: ${abs}`);
  return execFileSync('git', ['-C', abs, 'rev-parse', '--abbrev-ref', 'HEAD'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
}

/**
 * Split an invocation's `rest` into shell tokens, respecting quotes, so a
 * commit message like `-m "drop -a flag"` is one token, not a flag.
 */
function tokenizeArgs(rest) {
  const tokens = [];
  let pos = 0;
  while (pos < rest.length) {
    while (pos < rest.length && /\s/.test(rest[pos])) pos++;
    if (pos >= rest.length) break;
    const [tok, next] = readShellToken(rest, pos);
    if (tok === null) break;
    if (next <= pos) { pos++; continue; }
    tokens.push(tok);
    pos = next;
  }
  return tokens;
}

// Pathspecs that mean "everything" (from the repo root or the cwd).
const BLANKET_PATHSPECS = new Set(['.', './', ':/', ':', '*', ':/*', ':(top)']);

/**
 * Does a short-option cluster (`-am`, `-ku`) set one of `flags` before
 * reaching an option that consumes the rest of the cluster as its argument?
 * `-am msg` sets -a; `-ma` is -m with the message "a".
 */
function clusterSets(token, flags, argTaking) {
  if (!/^-[a-zA-Z]+$/.test(token)) return false;
  for (const ch of token.slice(1)) {
    if (flags.includes(ch)) return true;
    if (argTaking.includes(ch)) return false;
  }
  return false;
}

/**
 * Walk tokens, separating options from positionals. Options listed in
 * `argOpts` (short `-m`, long `--message`) consume the next token unless
 * written `--opt=value` / attached. Everything after `--` is positional.
 */
function splitArgs(tokens, argOpts) {
  const options = [];
  const positionals = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === '--') {
      positionals.push(...tokens.slice(i + 1));
      break;
    }
    if (t.startsWith('-') && t.length > 1) {
      options.push(t);
      if (argOpts.includes(t)) i++;
      else if (/^-[a-zA-Z]+$/.test(t)) {
        // Short cluster ending in an arg-taking option with nothing attached
        // (`-am "msg"`) consumes the next token.
        const last = t[t.length - 1];
        if (argOpts.includes(`-${last}`)) i++;
      }
      continue;
    }
    positionals.push(t);
  }
  return { options, positionals };
}

const COMMIT_ARG_OPTS = [
  '-m', '-F', '-C', '-c', '-t',
  '--message', '--file', '--author', '--date', '--reuse-message', '--reedit-message',
  '--fixup', '--squash', '--template', '--cleanup', '--trailer', '--pathspec-from-file',
];
const STASH_ARG_OPTS = ['-m', '--message', '--pathspec-from-file'];
const STASH_READ_ONLY = new Set(['list', 'show', 'create']);
const STASH_NON_PUSH = new Set(['drop', 'pop', 'apply', 'branch', 'clear', 'store']);

const SWEEPS_UNTRACKED = 'sweeps up every file on this checkout, including other sessions\' new untracked files.';
const SWEEPS_TRACKED = 'sweeps other sessions\' uncommitted changes to tracked files into your commit.';

/**
 * R4 classifier: returns { label, note? } for a git invocation that can
 * damage or sweep up other sessions' work on a shared checkout, else null.
 *
 * Destructive verbs (any form): stash, checkout, switch, reset --hard.
 * Sweeping forms — the counterpart to R1b allowing untracked edits, since
 * these are what DO catch untracked (and others' tracked) files:
 *   add -A/--all/-u/--update, add <blanket pathspec> (except -n/--dry-run)
 *   commit -a/--all, commit <blanket pathspec>
 *   clean (except -n/--dry-run)
 *   stash push/save -u/--include-untracked/-a/--all (labelled specially;
 *   plain stash already warns)
 */
/**
 * The checkouts a git invocation can reach, as a Set of canonical
 * toplevels, or null if that can't be determined.
 *   'checkout': the one working tree the command runs in (-C path or CWD).
 *   'repo':     every worktree of that repo (`git worktree list`).
 */
function affectedToplevels(cPath, scope) {
  try {
    const dir = cPath ? path.resolve(process.cwd(), cPath) : process.cwd();
    if (dir.startsWith('-')) return null;
    if (scope === 'repo') {
      const out = execFileSync('git', ['-C', dir, 'worktree', 'list', '--porcelain'], {
        encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'],
      });
      const tops = out.split('\n')
        .filter(l => l.startsWith('worktree '))
        .map(l => canonicalPath(l.slice('worktree '.length)));
      return tops.length > 0 ? new Set(tops) : null;
    }
    const top = execFileSync('git', ['-C', dir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    return new Set([canonicalPath(top)]);
  } catch {
    return null;
  }
}

const R4_SUBCOMMANDS = new Set(['reset', 'checkout', 'switch', 'add', 'commit', 'clean', 'stash']);

function classifyR4(inv) {
  const { subcommand, rest } = inv;
  if (!R4_SUBCOMMANDS.has(subcommand)) return null;
  const tokens = tokenizeArgs(rest);

  if (subcommand === 'reset') {
    return tokens.includes('--hard') ? { label: 'git reset --hard' } : null;
  }
  if (subcommand === 'checkout') return { label: 'git checkout' };
  if (subcommand === 'switch') return { label: 'git switch' };

  if (subcommand === 'add') {
    const { options, positionals } = splitArgs(tokens, ['--chmod', '--pathspec-from-file']);
    // add's short options take no arguments, so any cluster char counts.
    if (options.some(o => o === '-n' || o === '--dry-run' || clusterSets(o, ['n'], []))) return null;
    if (options.some(o => o === '-A' || o === '--all' || clusterSets(o, ['A'], []))) {
      return { label: 'git add -A', note: SWEEPS_UNTRACKED };
    }
    const blanket = positionals.find(p => BLANKET_PATHSPECS.has(p));
    if (blanket) return { label: `git add ${blanket}`, note: SWEEPS_UNTRACKED };
    if (options.some(o => o === '-u' || o === '--update' || clusterSets(o, ['u'], []))) {
      return { label: 'git add -u', note: SWEEPS_TRACKED };
    }
    return null;
  }

  if (subcommand === 'commit') {
    const { options, positionals } = splitArgs(tokens, COMMIT_ARG_OPTS);
    if (options.some(o => o === '-a' || o === '--all' || clusterSets(o, ['a'], ['m', 'F', 'C', 'c', 't']))) {
      return { label: 'git commit -a', note: SWEEPS_TRACKED };
    }
    const blanket = positionals.find(p => BLANKET_PATHSPECS.has(p));
    if (blanket) return { label: `git commit ${blanket}`, note: SWEEPS_TRACKED };
    return null;
  }

  if (subcommand === 'clean') {
    const dryRun = tokens.some(t => t === '-n' || t === '--dry-run' || clusterSets(t, ['n'], ['e']));
    return dryRun ? null : {
      label: 'git clean',
      note: 'deletes untracked files — including other sessions\' new files on this checkout.',
    };
  }

  if (subcommand === 'stash') {
    if (tokens.length > 0 && STASH_READ_ONLY.has(tokens[0])) return null;
    // The stash list is shared by every worktree of the repo, so pop/drop/
    // clear/store/branch can take or destroy another worktree's stash.
    if (tokens.length > 0 && STASH_NON_PUSH.has(tokens[0])) {
      return { label: `git stash ${tokens[0]}`, scope: 'repo' };
    }
    const { options } = splitArgs(tokens, STASH_ARG_OPTS);
    const untracked = options.some(o =>
      o === '-u' || o === '--include-untracked' || o === '-a' || o === '--all' ||
      clusterSets(o, ['u', 'a'], ['m'])
    );
    return untracked
      ? { label: 'git stash -u', note: 'stashes untracked files too — including other sessions\' new files.' }
      : { label: 'git stash' };
  }

  return null;
}

function handleBash(command, sessionId) {
  if (!command) {
    process.exit(0);
  }

  // R0: Block cd to a different git repo
  const check = checkCdEscape(extractCdTargets(command));
  if (check.blocked) {
    process.stderr.write(check.message);
    process.exit(2);
  }

  // Parse every `git <globals?> <subcommand> <rest>` invocation. R3/R4/R5
  // iterate over these rather than matching the raw command, so
  // `git -C <path> <verb>` (and --work-tree=, --git-dir= equivalents) are
  // handled uniformly — no global-option-placement bypass.
  const invocations = extractGitInvocations(command);

  // Accumulate warnings so R3 and R4 can both fire without writing two JSON
  // objects to stdout (which would corrupt the output).
  const warnings = [];

  // R3: Warn on `git push` targeting a protected branch. Filter by
  // subcommand, then match rule patterns against `rest` only.
  const protectedAlt = PROTECTED_BRANCHES
    .map(b => b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
  const pushToProtectedPatterns = [
    new RegExp(`^[\\w.-]+\\s+(?:${protectedAlt})\\b`),
    new RegExp(`^[\\w.-]+\\s+[^:\\s]+:(?:${protectedAlt})\\b`),
    new RegExp(`^--force[\\w-]*\\s+[\\w.-]+\\s+(?:${protectedAlt})\\b`),
    new RegExp(`^-f\\s+[\\w.-]+\\s+(?:${protectedAlt})\\b`),
  ];
  const barePushRestPattern = /^(\s*(-[a-zA-Z]+|--[\w-]+(=\S+)?))*\s*$/;

  let pushToProtectedHit = false;
  for (const inv of invocations) {
    if (inv.subcommand !== 'push') continue;
    if (pushToProtectedPatterns.some(p => p.test(inv.rest))) {
      pushToProtectedHit = true;
      break;
    }
  }

  let barePushOnProtected = false;
  if (!pushToProtectedHit) {
    for (const inv of invocations) {
      if (inv.subcommand !== 'push') continue;
      if (!barePushRestPattern.test(inv.rest)) continue;
      try {
        if (PROTECTED_BRANCHES.includes(resolveBranchForInvocation(inv.cPath))) {
          barePushOnProtected = true;
          break;
        }
      } catch {
        // Fail-open for warn-tier rules (R3): silently drop on branch-
        // resolution failure. Fail-closed is reserved for block-tier rules;
        // see R5's throw branch below.
      }
    }
  }

  if (pushToProtectedHit || barePushOnProtected) {
    warnings.push(
      '[GIT GUARD WARNING — PROTECTED BRANCH PUSH]\n' +
      'DO NOT STEAMROLL GIT-GUARD!\n' +
      'This push targets a configured protected branch (often an auto-deploy branch).\n' +
      'If that is not intentional, push to a feature branch and open a PR instead.'
    );
  }

  // R5: pointer-move guard. A `git pull <remote> <ref>` may only move the
  // target branch's pointer to an identically-named ref. Fails CLOSED on
  // branch-lookup failure — R5 exists because a silent pointer move can
  // cost many commits of drift.
  const { envs } = parseLeadingEnvVars(command);
  if (envs[POINTER_GUARD_OVERRIDE_ENV] !== '1') {
    for (const inv of invocations) {
      if (inv.subcommand !== 'pull') continue;
      const pullMatch = matchPullArgs(inv.rest);
      if (!pullMatch) continue;

      let branch;
      try {
        branch = resolveBranchForInvocation(inv.cPath);
      } catch {
        process.stderr.write(
          `[git-guard R5 BLOCKED] git pull detected but target branch could not be determined.\n` +
          (inv.cPath ? `  Target path: ${inv.cPath}\n` : '') +
          `Failing closed. Override: ${POINTER_GUARD_OVERRIDE_ENV}=1 <your command>\n`
        );
        process.exit(2);
      }
      if (pullMatch.src !== branch) {
        const targetDesc = inv.cPath ? `${branch} (at ${inv.cPath})` : branch;
        const pullSuggestion = inv.cPath
          ? `git -C ${inv.cPath} pull ${pullMatch.remote} ${branch}`
          : `git pull ${pullMatch.remote} ${branch}`;
        process.stderr.write(
          `[git-guard R5 BLOCKED] git pull would move ${targetDesc} to "${pullMatch.src}" (silent pointer move).\n` +
          `  Pull this branch:       ${pullSuggestion}\n` +
          `  Sync another branch:    run from inside its worktree, or use \`git fetch ${pullMatch.remote} <ref>:<ref>\`\n` +
          `  Cross-branch integrate: \`git merge origin/<other>\` or \`git rebase origin/<other>\` (not affected by R5)\n` +
          `  Override:               ${POINTER_GUARD_OVERRIDE_ENV}=1 <your command>\n`
        );
        process.exit(2);
      }
    }
  }

  // R4: Warn on destructive or sweeping verbs when other sessions are
  // active. Matches on subcommand + rest rather than a regex against the
  // raw command, so `git -C <path> stash` (etc.) doesn't bypass the check.
  // Collects every match so a chained `git add -A && git commit` names both.
  //
  // Only sessions the command can actually reach count: those on the same
  // checkout (scope 'checkout' — add, commit, clean, stash push, checkout,
  // switch, reset only touch the working tree they run in), or on any
  // worktree of the same repo (scope 'repo' — the shared stash list).
  // Sessions on other repos are not warned about.
  const matched = [];
  for (const inv of invocations) {
    const hit = classifyR4(inv);
    if (!hit) continue;
    const affected = affectedToplevels(inv.cPath, hit.scope || 'checkout');
    const prev = matched.find(m => m.label === hit.label);
    if (!prev) matched.push({ ...hit, affected });
    else if (prev.affected && affected) affected.forEach(t => prev.affected.add(t));
    else prev.affected = null;
  }
  if (matched.length > 0) {
    ensureStateDir();
    // affected === null means the target couldn't be resolved: fail toward
    // warning and count every other session, as R4 did before scoping.
    const anyUnknown = matched.some(m => m.affected === null);
    const reach = new Set(matched.flatMap(m => (m.affected ? [...m.affected] : [])));
    const others = getOtherSessions(sessionId)
      .filter(s => anyUnknown || reach.has(canonicalPath(s.toplevel)));
    if (others.length > 0) {
      const sessionList = others
        .map(s => `  - session ${s.session_id.slice(0, 8)}... on branch "${s.branch}" (${s.toplevel})`)
        .join('\n');
      const labels = matched.map(m => `"${m.label}"`).join(', ');
      const notes = matched
        .filter(m => m.note)
        .map(m => `${m.label}: ${m.note}\n`)
        .join('');
      warnings.push(
        `[GIT GUARD WARNING — OTHER SESSIONS ACTIVE]\n` +
        'DO NOT STEAMROLL GIT-GUARD!\n' +
        `You are about to run ${labels} but ${others.length} other active session(s) work where it reaches:\n` +
        `${sessionList}\n` +
        notes +
        `This command will affect their work. Proceed with caution.`
      );
    }
  }

  if (warnings.length > 0) {
    emitWarning(warnings.join('\n\n'));
  }
  process.exit(0);
}

async function main() {
  let input;
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    input = JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    process.exit(0);
  }

  const toolName = typeof input?.tool_name === 'string' ? input.tool_name : null;
  const toolInput = (input && typeof input.tool_input === 'object' && input.tool_input) || {};
  const sessionId = typeof input?.session_id === 'string' ? input.session_id : '';

  if (!toolName) process.exit(0);

  if (toolName === 'Edit' || toolName === 'Write') {
    const filePath = typeof toolInput.file_path === 'string' ? toolInput.file_path : null;
    handleEditWrite(sessionId, filePath);
  } else if (toolName === 'Bash') {
    const command = typeof toolInput.command === 'string' ? toolInput.command : null;
    // Guard against absurd inputs. Linear regexes on a 10MB string is still
    // wasted CPU; if a command is this large it's almost certainly not
    // something we should block on.
    if (command !== null && command.length <= MAX_COMMAND_BYTES) {
      handleBash(command, sessionId);
    } else {
      process.exit(0);
    }
  } else {
    process.exit(0);
  }
}

main().catch(() => process.exit(0));
