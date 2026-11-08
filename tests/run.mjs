#!/usr/bin/env node

// Test harness for git-guard.mjs.
//
// Each test sets up a temp git repo on a known branch, spawns the hook as
// a subprocess with a controlled stdin payload and cwd, asserts on exit
// code + stdout/stderr content, then cleans up.
//
// Run: npm test

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as url from 'node:url';

const HOOK = url.fileURLToPath(new URL('../git-guard.mjs', import.meta.url));

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
}

function initRepo(dir, branch) {
  spawnSync('git', ['-C', dir, 'init', '-b', branch], { stdio: 'pipe' });
  spawnSync('git', ['-C', dir, 'config', 'user.email', 'test@example.com'], { stdio: 'pipe' });
  spawnSync('git', ['-C', dir, 'config', 'user.name', 'Test'], { stdio: 'pipe' });
  spawnSync('git', ['-C', dir, 'commit', '--allow-empty', '-m', 'initial'], { stdio: 'pipe' });
}

// Add a linked worktree at <repo>/.worktrees/<name> on a new branch.
function addWorktree(repo, branch, name) {
  const wt = path.join(repo, '.worktrees', name);
  const r = spawnSync('git', ['-C', repo, 'worktree', 'add', '-q', '-b', branch, wt], { stdio: 'pipe' });
  if (r.status !== 0) throw new Error(`worktree add failed: ${r.stderr}`);
  return wt;
}

function runHook(payload, env = {}, cwd = undefined) {
  const r = spawnSync('node', [HOOK], {
    input: JSON.stringify(payload),
    env: { ...process.env, ...env },
    encoding: 'utf-8',
    cwd,
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`ok    ${name}`);
    passed++;
  } catch (e) {
    console.log(`FAIL  ${name}`);
    console.log(`      ${e.message}`);
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function git(repo, ...args) {
  const r = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf-8', stdio: 'pipe' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout.trim();
}

// Fake another active session by writing its state file, exactly as the
// hook would after that session's first Edit/Write on `repo`.
function fakeOtherSession(stateDir, repo, sessionId = 'other-session-0001') {
  const toplevel = git(repo, 'rev-parse', '--show-toplevel');
  const branch = git(repo, 'rev-parse', '--abbrev-ref', 'HEAD');
  fs.writeFileSync(
    path.join(stateDir, `${sessionId}-fake.json`),
    JSON.stringify({ branch, session_id: sessionId, toplevel, recorded_at: Date.now() })
  );
}

// A repo on a feature branch with one committed file and a .gitignore,
// plus a state dir in which another session is active on the same checkout.
function sharedCheckout() {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  initRepo(repo, 'feat/shared');
  fs.writeFileSync(path.join(repo, 'README.md'), 'tracked\n');
  fs.writeFileSync(path.join(repo, '.gitignore'), 'ignored/\n*.log\n');
  git(repo, 'add', 'README.md', '.gitignore');
  git(repo, 'commit', '-q', '-m', 'files');
  fakeOtherSession(state, repo);
  return { repo, state };
}

function editPayload(filePath, sessionId = 'me') {
  return { tool_name: 'Edit', tool_input: { file_path: filePath }, session_id: sessionId };
}

// R4 warnings arrive as stdout JSON; return the reason text ('' if none).
function warningText(r) {
  if (!r.stdout) return '';
  return JSON.parse(r.stdout).hookSpecificOutput?.permissionDecisionReason || '';
}

// --- R1 ---

test('R1: edit on main is blocked', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'main');
    const r = runHook(
      { tool_name: 'Edit', tool_input: { file_path: path.join(repo, 'foo.txt') }, session_id: 'r1' },
      { GIT_GUARD_STATE_DIR: state }
    );
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
    assert(r.stderr.includes('R1 BLOCKED'), 'expected R1 BLOCKED in stderr');
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1: edit on feature branch is allowed', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/test');
    const r = runHook(
      { tool_name: 'Edit', tool_input: { file_path: path.join(repo, 'foo.txt') }, session_id: 'r1-allow' },
      { GIT_GUARD_STATE_DIR: state }
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1: GIT_GUARD_PROTECTED_BRANCHES=master blocks edit on master', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'master');
    const r = runHook(
      { tool_name: 'Edit', tool_input: { file_path: path.join(repo, 'foo.txt') }, session_id: 'r1-master' },
      { GIT_GUARD_STATE_DIR: state, GIT_GUARD_PROTECTED_BRANCHES: 'master' }
    );
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
    assert(r.stderr.includes('R1 BLOCKED'), 'expected R1 BLOCKED');
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

// --- R1b (shared checkout: tracked files only) ---

test('R1b: tracked file on a shared checkout is blocked', () => {
  const { repo, state } = sharedCheckout();
  try {
    const r = runHook(editPayload(path.join(repo, 'README.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
    assert(r.stderr.includes('R1b BLOCKED'), 'expected R1b BLOCKED');
    assert(r.stderr.includes('is tracked by git'), 'expected tracked reason');
    assert(r.stderr.includes('other-se'), 'expected other session listed');
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: Write of a new untracked file on a shared checkout is allowed', () => {
  const { repo, state } = sharedCheckout();
  try {
    fs.mkdirSync(path.join(repo, 'docs'));
    const r = runHook(
      { tool_name: 'Write', tool_input: { file_path: path.join(repo, 'docs', 'draft.md') }, session_id: 'me' },
      { GIT_GUARD_STATE_DIR: state }
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: Edit of an existing untracked file on a shared checkout is allowed', () => {
  const { repo, state } = sharedCheckout();
  try {
    fs.writeFileSync(path.join(repo, 'notes.md'), 'untracked\n');
    const r = runHook(editPayload(path.join(repo, 'notes.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: gitignored file on a shared checkout is allowed', () => {
  const { repo, state } = sharedCheckout();
  try {
    fs.mkdirSync(path.join(repo, 'ignored'));
    fs.writeFileSync(path.join(repo, 'ignored', 'scratch.txt'), 'x\n');
    const r1 = runHook(editPayload(path.join(repo, 'ignored', 'scratch.txt')), { GIT_GUARD_STATE_DIR: state });
    assert(r1.code === 0, `ignored dir: expected exit 0, got ${r1.code}; stderr: ${r1.stderr}`);
    const r2 = runHook(editPayload(path.join(repo, 'run.log')), { GIT_GUARD_STATE_DIR: state });
    assert(r2.code === 0, `ignored glob: expected exit 0, got ${r2.code}; stderr: ${r2.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: staged-but-uncommitted file on a shared checkout is blocked', () => {
  const { repo, state } = sharedCheckout();
  try {
    fs.writeFileSync(path.join(repo, 'staged.md'), 'new\n');
    git(repo, 'add', 'staged.md');
    const r = runHook(editPayload(path.join(repo, 'staged.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
    assert(r.stderr.includes('R1b BLOCKED'), 'expected R1b BLOCKED');
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: force-added gitignored file is tracked and blocked', () => {
  const { repo, state } = sharedCheckout();
  try {
    fs.writeFileSync(path.join(repo, 'keep.log'), 'x\n');
    git(repo, 'add', '-f', 'keep.log');
    const r = runHook(editPayload(path.join(repo, 'keep.log')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: glob characters in an untracked name do not match tracked files', () => {
  const { repo, state } = sharedCheckout();
  try {
    // Unquoted pathspec `READ*.md` would match tracked README.md.
    const r = runHook(editPayload(path.join(repo, 'READ*.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: tracked file reached through a symlink is blocked', () => {
  const { repo, state } = sharedCheckout();
  try {
    fs.mkdirSync(path.join(repo, 'ignored'));
    fs.symlinkSync(path.join(repo, 'README.md'), path.join(repo, 'ignored', 'link.md'));
    const r = runHook(editPayload(path.join(repo, 'ignored', 'link.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 2, `expected exit 2, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: case-variant name of a tracked file is blocked (case-insensitive FS only)', () => {
  const { repo, state } = sharedCheckout();
  try {
    if (!fs.existsSync(path.join(repo, 'readme.md'))) {
      console.log('      (skipped: filesystem is case-sensitive)');
      return;
    }
    const r = runHook(editPayload(path.join(repo, 'readme.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 2, `expected exit 2, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: trackedness check error fails closed (blocked)', () => {
  const { repo, state } = sharedCheckout();
  try {
    // A corrupt index makes ls-files fail while rev-parse (branch lookup)
    // still works, so the hook reaches R1b and the check itself errors.
    fs.writeFileSync(path.join(repo, '.git', 'index'), 'garbage');
    const r = runHook(editPayload(path.join(repo, 'notes.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 2, `expected exit 2, got ${r.code}; stderr: ${r.stderr}`);
    assert(r.stderr.includes('R1b BLOCKED'), 'expected R1b BLOCKED');
    assert(r.stderr.includes('failing closed'), 'expected fail-closed reason');
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: tracked file is allowed when no other session is active', () => {
  const { repo, state } = sharedCheckout();
  try {
    for (const f of fs.readdirSync(state)) fs.unlinkSync(path.join(state, f));
    const r = runHook(editPayload(path.join(repo, 'README.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R1b: tracked file in a worktree is allowed even with other sessions active', () => {
  const { repo, state } = sharedCheckout();
  try {
    const wt = addWorktree(repo, 'feat/mine', 'mine');
    const r = runHook(editPayload(path.join(wt, 'README.md')), { GIT_GUARD_STATE_DIR: state });
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

// --- R0 ---

test('R0: cd to a different repo is blocked', () => {
  const repo1 = tmpDir('cggt-');
  const repo2 = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo1, 'feat/x');
    initRepo(repo2, 'feat/y');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `cd ${repo2} && git status` }, session_id: 'r0' },
      { GIT_GUARD_STATE_DIR: state },
      repo1
    );
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
    assert(r.stderr.includes('R0 BLOCKED'), 'expected R0 BLOCKED');
  } finally {
    cleanup(repo1);
    cleanup(repo2);
    cleanup(state);
  }
});

test('R0: cd from main checkout into its own worktree is allowed', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const wt = addWorktree(repo, 'feat/wt', 'wt');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `cd ${wt} && git status` }, session_id: 'r0-wt-in' },
      { GIT_GUARD_STATE_DIR: state },
      repo
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R0: cd from a worktree back to the main checkout is allowed', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const wt = addWorktree(repo, 'feat/wt', 'wt');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `cd ${repo} && git status` }, session_id: 'r0-wt-out' },
      { GIT_GUARD_STATE_DIR: state },
      wt
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R0: cd between sibling worktrees is allowed', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const wtA = addWorktree(repo, 'feat/a', 'a');
    const wtB = addWorktree(repo, 'feat/b', 'b');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `cd ${wtB}` }, session_id: 'r0-sib' },
      { GIT_GUARD_STATE_DIR: state },
      wtA
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R0: cd from a worktree into a different repo is still blocked', () => {
  const repo = tmpDir('cggt-');
  const other = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    initRepo(other, 'feat/y');
    const wt = addWorktree(repo, 'feat/wt', 'wt');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `cd ${other} && git status` }, session_id: 'r0-wt-foreign' },
      { GIT_GUARD_STATE_DIR: state },
      wt
    );
    assert(r.code === 2, `expected exit 2, got ${r.code}`);
    assert(r.stderr.includes('R0 BLOCKED'), 'expected R0 BLOCKED');
    assert(r.stderr.includes(other), 'expected target repo toplevel in message');
  } finally {
    cleanup(repo);
    cleanup(other);
    cleanup(state);
  }
});

test('R0: cd to a case-variant path of the same repo is allowed (case-insensitive FS only)', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const variant = path.join(path.dirname(repo), path.basename(repo).toUpperCase());
    if (!fs.existsSync(variant)) {
      console.log('      (skipped: filesystem is case-sensitive)');
      return;
    }
    const wt = addWorktree(repo, 'feat/wt', 'wt');
    // Hook runs in the worktree; target is the main checkout spelled in a
    // different case. Common git dirs must canonicalize to the same path.
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `cd ${variant}` }, session_id: 'r0-case' },
      { GIT_GUARD_STATE_DIR: state },
      wt
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

// --- R3 (warning via JSON output) ---

test('R3: push to protected branch emits allow+reason JSON', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/test');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: 'git push origin main' }, session_id: 'r3' },
      { GIT_GUARD_STATE_DIR: state },
      repo
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert(out.hookSpecificOutput?.permissionDecision === 'allow', 'expected permissionDecision=allow');
    assert(
      (out.hookSpecificOutput?.permissionDecisionReason || '').includes('PROTECTED BRANCH PUSH'),
      'expected PROTECTED BRANCH PUSH in reason'
    );
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

// --- R5 ---

test('R5: pull wrong ref is blocked', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: 'git pull origin feat/y' }, session_id: 'r5' },
      { GIT_GUARD_STATE_DIR: state },
      repo
    );
    assert(r.code === 2, `expected exit 2, got ${r.code}; stderr: ${r.stderr}`);
    assert(r.stderr.includes('R5 BLOCKED'), 'expected R5 BLOCKED');
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R5: git -C <path> pull wrong ref is blocked (branch read at <path>)', () => {
  const repo = tmpDir('cggt-');
  const elsewhere = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    initRepo(elsewhere, 'feat/y');
    // Hook CWD is on feat/y; the -C target is on feat/x. Pulling feat/y
    // into the -C target is a pointer move even though it matches the CWD.
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: `git -C ${repo} pull origin feat/y` }, session_id: 'r5-C' },
      { GIT_GUARD_STATE_DIR: state },
      elsewhere
    );
    assert(r.code === 2, `expected exit 2, got ${r.code}; stderr: ${r.stderr}`);
    assert(r.stderr.includes('R5 BLOCKED'), 'expected R5 BLOCKED');
  } finally {
    cleanup(repo);
    cleanup(elsewhere);
    cleanup(state);
  }
});

test('R5: override prefix allows pull wrong ref', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: 'GIT_GUARD_ALLOW_POINTER_MOVE=1 git pull origin feat/y' }, session_id: 'r5-override' },
      { GIT_GUARD_STATE_DIR: state },
      repo
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

test('R5: matching-ref pull is allowed', () => {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    const r = runHook(
      { tool_name: 'Bash', tool_input: { command: 'git pull origin feat/x' }, session_id: 'r5-match' },
      { GIT_GUARD_STATE_DIR: state },
      repo
    );
    assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(repo);
    cleanup(state);
  }
});

// --- R4 (warning when other sessions are active) ---

const R4_WARN_CASES = [
  // [args after `git`, label expected in the warning]
  ['add -A', 'git add -A'],
  ['add --all', 'git add -A'],
  ['add -vA', 'git add -A'],
  ['add .', 'git add .'],
  ['add -- .', 'git add .'],
  ['add :/', 'git add :/'],
  ['add -u', 'git add -u'],
  ['add --update', 'git add -u'],
  ['commit -a -m "msg"', 'git commit -a'],
  ['commit --all -m msg', 'git commit -a'],
  ['commit -am "msg"', 'git commit -a'],
  ['commit -m msg .', 'git commit .'],
  ['clean -fd', 'git clean'],
  ['clean -f -x', 'git clean'],
  ['stash -u', 'git stash -u'],
  ['stash push --include-untracked', 'git stash -u'],
  ['stash --all', 'git stash -u'],
  ['stash save -u "wip"', 'git stash -u'],
  ['stash', 'git stash'],
  ['reset --hard', 'git reset --hard'],
  ['reset -q --hard HEAD', 'git reset --hard'],
  ['checkout other', 'git checkout'],
];

const R4_SILENT_CASES = [
  'add README.md',
  'add -n .',
  'add --dry-run -A',
  'commit -m "drop the -a flag from add ."',
  'commit -ma',
  'commit -m msg README.md',
  'clean -n',
  'clean -nfd',
  'clean --dry-run',
  'reset HEAD~1',
  'status',
];

function r4Run(command, withOthers = true) {
  const repo = tmpDir('cggt-');
  const state = tmpDir('cggs-');
  try {
    initRepo(repo, 'feat/x');
    if (withOthers) fakeOtherSession(state, repo);
    const cmd = command.replaceAll('{repo}', repo);
    return runHook(
      { tool_name: 'Bash', tool_input: { command: cmd }, session_id: 'me' },
      { GIT_GUARD_STATE_DIR: state },
      repo
    );
  } finally {
    cleanup(repo);
    cleanup(state);
  }
}

for (const [args, label] of R4_WARN_CASES) {
  for (const prefix of ['git', 'git -C {repo}']) {
    test(`R4: "${prefix} ${args}" warns as "${label}"`, () => {
      const r = r4Run(`${prefix} ${args}`);
      assert(r.code === 0, `expected exit 0 (warn, not block), got ${r.code}; stderr: ${r.stderr}`);
      const text = warningText(r);
      assert(text.includes('OTHER SESSIONS ACTIVE'), `expected R4 warning, got stdout: ${r.stdout}`);
      assert(text.includes(`"${label}"`), `expected label "${label}" in: ${text}`);
    });
  }
}

for (const args of R4_SILENT_CASES) {
  for (const prefix of ['git', 'git -C {repo}']) {
    test(`R4: "${prefix} ${args}" does not warn`, () => {
      const r = r4Run(`${prefix} ${args}`);
      assert(r.code === 0, `expected exit 0, got ${r.code}; stderr: ${r.stderr}`);
      assert(!warningText(r).includes('OTHER SESSIONS ACTIVE'), `unexpected R4 warning: ${r.stdout}`);
    });
  }
}

test('R4: --work-tree= form warns', () => {
  const r = r4Run('git --work-tree={repo} add -A');
  assert(warningText(r).includes('"git add -A"'), `expected R4 warning, got: ${r.stdout}`);
});

test('R4: sweeping commands explain what they sweep', () => {
  const r = r4Run('git add -A');
  assert(warningText(r).includes('untracked'), `expected untracked note, got: ${warningText(r)}`);
});

test('R4: chained add -A && commit -a names both commands', () => {
  const r = r4Run('git add -A && git commit -a -m wip');
  const text = warningText(r);
  assert(text.includes('"git add -A"') && text.includes('"git commit -a"'), `expected both labels, got: ${text}`);
});

test('R4: no warning when no other session is active', () => {
  const r = r4Run('git add -A', false);
  assert(r.code === 0, `expected exit 0, got ${r.code}`);
  assert(r.stdout === '', `expected no output, got: ${r.stdout}`);
});

// --- fail-open paths ---

test('fail-open: malformed JSON on stdin', () => {
  const r = spawnSync('node', [HOOK], { input: 'not json', encoding: 'utf-8' });
  assert(r.status === 0, `expected exit 0, got ${r.status}`);
});

test('fail-open: edit outside any git repo', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cggn-'));
  try {
    const r = runHook({
      tool_name: 'Edit',
      tool_input: { file_path: path.join(dir, 'foo.txt') },
      session_id: 'no-git',
    });
    assert(r.code === 0, `expected exit 0 (fail-open), got ${r.code}; stderr: ${r.stderr}`);
  } finally {
    cleanup(dir);
  }
});

// --- summary ---

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
