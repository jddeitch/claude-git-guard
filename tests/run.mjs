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
