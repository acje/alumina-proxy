#!/usr/bin/env node
// Regression fixture for the structural HTML gate (scripts/html_check.mjs).
// Node builtins only (spawnSync, fs, path); no npm, no package.json, run
// directly as `node scripts/html_check_test.mjs`. Not wired into verify.sh's
// dispatch arms — identity-tracked and hand-run, same convention as
// scripts/docs_check/test.mjs. One case per check plus one per review probe
// (adversarial round 3, B1). Every case asserts the exit code AND the stdout
// marker the behaviour must emit (or must not emit for the honesty rules).
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'

const repoRoot = process.cwd()
const checker = process.env.HTML_CHECK_JS || path.join(repoRoot, 'scripts/html_check.mjs')
const base = await mkdtemp(path.join(repoRoot, 'target', 'htmlctl-'))
let failures = 0
let ran = 0

function expect(name, files, wantExit, opts) {
  ran++
  const res = spawnSync(process.execPath, [checker, ...files], { cwd: base, encoding: 'utf8' })
  const got = res.status
  const out = res.stdout || ''
  const err = res.stderr || ''
  const has = (opts.has || []).every((s) => out.includes(s))
  const no = (opts.no || []).every((s) => !out.includes(s))
  const ok = got === wantExit && has && no
  if (!ok) {
    failures++
    console.error(
      `HTML-CHECK-TEST-FAIL ${name}: got exit ${got} (want ${wantExit}) has=${has} no=${no}` +
        `\n  out: ${out.split('\n').filter(Boolean).join(' | ')}` +
        `\n  err: ${err.split('\n').filter(Boolean).join(' | ')}`
    )
  } else {
    console.log(`HTML-CHECK-TEST-PASS ${name} (exit ${got})`)
  }
}

try {
  await writeFile(
    path.join(base, 'clean.html'),
    ['<!doctype html>', '<html>', '  <body>', '    <p id="a">hello</p>', '  </body>', '</html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'stray.html'),
    ['<!doctype html>', '<html><body>', '</div>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'mismatch.html'),
    ['<!doctype html>', '<html><body><div><span>', '</div>', '</span></body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'two_roots.html'),
    ['<!doctype html>', '<html><body></body></html>', '<div></div>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'dup_id.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<div id="d"></div><img id="d" src="x.png">',
      '<circle id="c"/><rect id="c"/>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'dangling.html'),
    ['<!doctype html>', '<html><body><a href="#nope">x</a>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'resolve_id.html'),
    ['<!doctype html>', '<html><body>', '<p id="ok">target</p>', '<a href="#ok">link</a>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'resolve_name.html'),
    ['<!doctype html>', '<html><body>', '<a name="nm"></a>', '<a href="#nm">link</a>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'fig_nodec.html'),
    ['<!doctype html>', '<html><body>', '<figure><svg></svg></figure>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'desc_out.html'),
    ['<!doctype html>', '<html><body>', '<desc></desc>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'cells_bad.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>A</th><th>B</th></tr></thead>',
      '  <tbody><tr><td>1</td><td>2</td></tr><tr><td>3</td></tr></tbody>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  // B1 no-op shapes (must FAIL now; each was a silent clean pass before the fix):
  await writeFile(
    path.join(base, 'b1_implicit.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>A</th><th>B</th></tr></thead>',
      '  <tr><td>x</td></tr>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'b1_tfoot.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>A</th><th>B</th></tr></thead>',
      '  <tbody><tr><td>1</td><td>2</td></tr></tbody>',
      '  <tfoot><tr><td>total</td></tr></tfoot>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'b1_thead_notr.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><th>A</th><th>B</th></thead>',
      '  <tbody><tr><td>1</td></tr></tbody>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'colspan.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>A</th><th>B</th></tr></thead>',
      '  <tbody><tr><td colspan="2">z</td></tr></tbody>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )

  expect('clean-minimal document', ['clean.html'], 0, {
    has: ['HTML-CHECK-OK clean.html', 'clean 1'],
    no: ['HTML-STRUCT-FAIL', 'HTML-CHECK-OP-FAIL'],
  })
  expect('check1 unmatched close tag (stray-close)', ['stray.html'], 1, { has: ['stray-close'] })
  expect('check1 wrong-name close tag (tag-mismatch)', ['mismatch.html'], 1, { has: ['tag-mismatch'] })
  expect('check1 second root element (root-count)', ['two_roots.html'], 1, { has: ['root-count', '2 root elements'] })
  expect('check2 duplicate id (void + self-closing second sites)', ['dup_id.html'], 1, { has: ['duplicate-id'] })
  expect('check3 dangling fragment fails', ['dangling.html'], 1, { has: ['dangling-fragment', 'href="#nope"'] })
  expect('check3 resolvable fragment via id is clean', ['resolve_id.html'], 0, {
    has: ['HTML-CHECK-OK resolve_id.html'],
    no: ['HTML-STRUCT-FAIL'],
  })
  expect('check3 resolvable fragment via name is clean', ['resolve_name.html'], 0, {
    has: ['HTML-CHECK-OK resolve_name.html'],
    no: ['HTML-STRUCT-FAIL'],
  })
  expect('check4 figure without desc fails', ['fig_nodec.html'], 1, { has: ['missing-desc'] })
  expect('check4 desc outside any figure is clean', ['desc_out.html'], 0, {
    has: ['HTML-CHECK-OK desc_out.html'],
    no: ['HTML-STRUCT-FAIL'],
  })
  expect('check5 tbody cell-count mismatch fails', ['cells_bad.html'], 1, { has: ['table-cell-count'] })
  expect('check5 B1 implicit tbody row is a checked body row', ['b1_implicit.html'], 1, { has: ['table-cell-count'] })
  expect('check5 B1 tfoot row is a checked body row', ['b1_tfoot.html'], 1, { has: ['table-cell-count'] })
  expect('check5 B1 thead without a tr cell row is table-header-missing', ['b1_thead_notr.html'], 1, {
    has: ['table-header-missing'],
  })

  expect('exit2 missing file: op-fail, no OK, clean 0', ['nope-missing.html'], 2, {
    has: ['HTML-CHECK-OP-FAIL', 'clean 0'],
    no: ['HTML-CHECK-OK'],
  })
  expect('exit2 colspan: op-fail, no OK, clean 0', ['colspan.html'], 2, {
    has: ['HTML-CHECK-OP-FAIL', 'not clean', 'clean 0'],
    no: ['HTML-CHECK-OK'],
  })

  const staticRes = spawnSync('rg', ['-n', 'child_process|execSync|spawn|new Function|node:http|node:https', checker], { encoding: 'utf8' })
  ran++
  if (staticRes.status === 1) {
    console.log('HTML-CHECK-TEST-PASS static-no-exec (rg no-match, exit 1)')
  } else if (staticRes.status === 0) {
    failures++
    console.error(`HTML-CHECK-TEST-FAIL static-no-exec: adapter source contains runtime exec/network imports:\n${staticRes.stdout}`)
  } else {
    failures++
    console.error(`HTML-CHECK-TEST-FAIL static-no-exec: rg producer error status ${staticRes.status} (exit 0 was blocked; a search error cannot pass)`)
  }
} finally {
  await rm(base, { recursive: true, force: true })
}

if (failures > 0) {
  console.error(`HTML-CHECK-TEST-FAIL (${failures}/${ran} cases failed)`)
  process.exit(1)
}
console.log(`HTML-CHECK-TEST-OK (${ran} cases)`)
process.exit(0)
