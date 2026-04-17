#!/usr/bin/env node

// claude-git-guard — Claude Code PreToolUse hook for multi-agent safety.
//
// https://github.com/jddeitch/claude-git-guard
//
// Edit|Write path — Hard gates:
//   R1   Block edits on a protected branch
//   R1b  Block shared-checkout edits (force other sessions into worktrees)
//   R2   Block if branch drifted since session start
//
// Bash path — mixed:
//   R0   BLOCK cd to a different git repo
//   R3   WARN before `git push` targeting a protected branch
//   R5   BLOCK `git pull <remote> <ref>` on ANY branch when ref differs
//        from the current branch name. Override via
//        GIT_GUARD_ALLOW_POINTER_MOVE=1 prefix.
//   R4   WARN on destructive verbs (stash/checkout/switch/reset --hard)
//        when other sessions are active
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
  const dir = filePath ? path.dirname(filePath) : process.cwd();
  const toplevel = execFileSync('git', ['-C', dir, 'rev-parse', '--show-toplevel'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
  const branch = execFileSync('git', ['-C', toplevel, 'rev-parse', '--abbrev-ref', 'HEAD'], {
    encoding: 'utf-8', timeout: 5000,
  }).trim();
  return { toplevel, branch };
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

function writeSessionState(key, branch, sessionId, toplevel) {
  try {
    const fp = path.join(STATE_DIR, `${key}.json`);
    fs.writeFileSync(fp, JSON.stringify({
      branch,
      session_id: sessionId,
      toplevel,
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

  if (!isWorktree) {
    const othersOnSameToplevel = getOtherSessions(sessionId)
      .filter(s => s.toplevel === toplevel);
    if (othersOnSameToplevel.length > 0) {
      const sessionList = othersOnSameToplevel
        .map(s => `  - session ${s.session_id.slice(0, 8)}... on branch "${s.branch}"`)
        .join('\n');
      process.stderr.write(
        `[git-guard R1b BLOCKED] ${othersOnSameToplevel.length} other session(s) active on this checkout:\n` +
        `${sessionList}\n\n` +
        'DO NOT STEAMROLL GIT-GUARD!\n' +
        'Multiple agents on the same checkout cause branch collisions.\n' +
        'Use your agent\'s worktree tool, or `git worktree add -b feat/<name> .worktrees/<name>`.\n' +
        'Do NOT just create a branch in place — that moves every session listed above onto your branch.\n' +
        'Do NOT delete state files or work around this.\n'
      );
      process.exit(2);
    }
  }

  // R2: Branch drift detection
  const state = readSessionState(key);

  if (!state) {
    writeSessionState(key, branch, sessionId, toplevel);
    process.exit(0);
  }

  if (state.branch === branch) {
    process.exit(0);
  }

  // `git branch -m` deletes the old ref — if it's gone, rename, not drift.
  try {
    execFileSync('git', ['-C', toplevel, 'rev-parse', '--verify', `refs/heads/${state.branch}`], {
      encoding: 'utf-8', timeout: 5000, stdio: 'pipe',
    });
  } catch {
    writeSessionState(key, branch, sessionId, toplevel);
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
 * Extract the cd target from a command string.
 * Handles: cd /path, cd /path && ..., cd /path ; ..., cd "/path with spaces"
 * Returns null if no cd found or target can't be statically resolved.
 */
function extractCdTarget(command) {
  const cdMatch = command.match(/(?:^|&&|;|\|\|)\s*cd\s+(?:"([^"]+)"|'([^']+)'|(\S+))/);
  if (!cdMatch) return null;
  const target = cdMatch[1] || cdMatch[2] || cdMatch[3];
  if (!target) return null;
  if (target.includes('$') || target.includes('`')) return null;
  if (target.startsWith('~')) return null;
  return target;
}

/**
 * Check if a cd target would leave the current git repo.
 * Returns { blocked: true, message } if it would, { blocked: false } otherwise.
 */
function checkCdEscape(cdTarget) {
  let absTarget;
  if (path.isAbsolute(cdTarget)) {
    absTarget = cdTarget;
  } else {
    absTarget = path.resolve(process.cwd(), cdTarget);
  }

  try {
    if (!fs.statSync(absTarget).isDirectory()) return { blocked: false };
  } catch {
    return { blocked: false };
  }

  let currentToplevel;
  try {
    currentToplevel = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      encoding: 'utf-8', timeout: 5000,
    }).trim();
  } catch {
    return { blocked: false };
  }

  // execFileSync (argv, no shell) so a cd target containing shell
  // metacharacters can't break out.
  let targetToplevel;
  try {
    targetToplevel = execFileSync('git', ['-C', absTarget, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8', timeout: 5000,
    }).trim();
  } catch {
    return { blocked: false };
  }

  if (currentToplevel === targetToplevel) return { blocked: false };

  return {
    blocked: true,
    message:
      `[git-guard R0 BLOCKED] "cd ${cdTarget}" would move to a different git repo.\n` +
      `  Current repo: ${currentToplevel}\n` +
      `  Target repo:  ${targetToplevel}\n\n` +
      'DO NOT STEAMROLL GIT-GUARD!\n' +
      'This will cause all subsequent git commands to operate on the wrong repo.\n' +
      'Use absolute paths instead of cd, or run commands in a separate worktree.\n',
  };
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
function readShellToken(command, pos) {
  if (pos >= command.length) return [null, pos];
  const first = command[pos];
  if (first === '"' || first === "'") {
    const start = pos + 1;
    const endIdx = command.indexOf(first, start);
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

    const restStart = pos;
    while (pos < command.length && !/[;&|()`]/.test(command[pos])) pos++;
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

function handleBash(command, sessionId) {
  if (!command) {
    process.exit(0);
  }

  // R0: Block cd to a different git repo
  const cdTarget = extractCdTarget(command);
  if (cdTarget) {
    const check = checkCdEscape(cdTarget);
    if (check.blocked) {
      process.stderr.write(check.message);
      process.exit(2);
    }
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

  // R4: Warn on destructive verbs when other sessions are active. Matches
  // on subcommand + rest rather than a regex against the raw command, so
  // `git -C <path> stash` (etc.) no longer bypasses the check.
  const destructiveLabels = { stash: 'git stash', checkout: 'git checkout', switch: 'git switch' };
  let matchedDestructive = null;
  for (const inv of invocations) {
    if (inv.subcommand === 'reset' && /^--hard\b/.test(inv.rest)) {
      matchedDestructive = { label: 'git reset --hard' };
      break;
    }
    // Object.hasOwn rather than `in` — subcommand is user-controlled text,
    // `__proto__` and `constructor` would otherwise match the label table.
    if (Object.hasOwn(destructiveLabels, inv.subcommand)) {
      matchedDestructive = { label: destructiveLabels[inv.subcommand] };
      break;
    }
  }
  if (matchedDestructive) {
    ensureStateDir();
    const others = getOtherSessions(sessionId);
    if (others.length > 0) {
      const sessionList = others
        .map(s => `  - session ${s.session_id.slice(0, 8)}... on branch "${s.branch}"`)
        .join('\n');
      warnings.push(
        `[GIT GUARD WARNING — OTHER SESSIONS ACTIVE]\n` +
        'DO NOT STEAMROLL GIT-GUARD!\n' +
        `You are about to run "${matchedDestructive.label}" but there are ${others.length} other active session(s):\n` +
        `${sessionList}\n` +
        `This command will affect their working tree. Proceed with caution.`
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
