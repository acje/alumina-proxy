#!/usr/bin/env node
// Regression fixture for the structural HTML gate (scripts/html_check.mjs).
// Node builtins only (spawnSync, fs, path); no npm, no package.json, run
// directly as `node scripts/html_check_test.mjs`. Not wired into verify.sh's
// dispatch arms — identity-tracked and hand-run, same convention as
// scripts/docs_check/test.mjs. One case per check plus one per review probe
// (adversarial round 3, B1; round-4 M1 adds row-header and positive cases).
// Every case asserts the exit code AND the stdout
// marker the behaviour must emit (or must not emit for the honesty rules).
import { spawnSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
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
  // M1 (review round 4) — check-5 coverage was negative-only; a mutant flagging
  // every body row scored 17/17 and a row-header regression would silently
  // uncheck 126/140 corpus rows. Three cases: (1) a <tbody> row whose
  // <th scope="row"> is a counted cell, (2) a correct <tfoot> row must be
  // accepted, (3) a correctly-sized nested table must be accepted.
  await writeFile(
    path.join(base, 'rowheader_short.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>A</th><th>B</th><th>C</th></tr></thead>',
      '  <tbody><tr><th scope="row">R</th><td>1</td></tr></tbody>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'tfoot_ok.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>A</th><th>B</th></tr></thead>',
      '  <tbody><tr><td>1</td><td>2</td></tr></tbody>',
      '  <tfoot><tr><td>x</td><td>y</td></tr></tfoot>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'nested_ok.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<table>',
      '  <thead><tr><th>O1</th><th>O2</th><th>O3</th></tr></thead>',
      '  <tbody>',
      '    <tr>',
      '      <td>a</td>',
      '      <td>',
      '        <table>',
      '          <thead><tr><th>I1</th><th>I2</th></tr></thead>',
      '          <tbody><tr><td>x</td><td>y</td></tr></tbody>',
      '        </table>',
      '      </td>',
      '      <td>c</td>',
      '    </tr>',
      '  </tbody>',
      '</table>',
      '</body></html>',
      '',
    ].join('\n')
  )
  // Check 6 (citation bounds) and check 7 (banned issue apparatus) fixtures.
  // one.rs is a 1-line cited target; foo.rs tests the src/ fallback; locked.rs
  // is rendered unreadable (chmod 000) to prove the operational split (exit 2)
  // stays distinct from a domain-negative (exit 1).
  await writeFile(path.join(base, 'one.rs'), '// one line\n')
  await writeFile(
    path.join(base, 'cite_ok.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>one.rs:1</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'cite_missing.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>nope.rs:1</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'cite_out_of_range.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>one.rs:99</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'cite_malformed.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>one.rs:5-2</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(path.join(base, 'locked.rs'), '// locked\n')
  await chmod(path.join(base, 'locked.rs'), 0o000)
  await writeFile(
    path.join(base, 'cite_locked.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>locked.rs:1</code>.</p>', '</body></html>', ''].join('\n')
  )
  await mkdir(path.join(base, 'src'))
  await writeFile(path.join(base, 'src', 'foo.rs'), '// foo\n')
  await writeFile(
    path.join(base, 'cite_src.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>foo.rs:1</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'apparatus.html'),
    [
      '<!doctype html>',
      '<html><body>',
      '<p>F-01 U-02 alumina-abcde (S1) owner decision review finding recommendation</p>',
      '</body></html>',
      '',
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'apparatus_fp.html'),
    ['<!doctype html>', '<html><body>', '<p>alumina-proxy and docs/alumina-proxy.md</p>', '</body></html>', ''].join('\n')
  )
  // H1 (adversarial round 5, blocking) — `./`-prefixed citation heads must be
  // parsed, not silently skipped. cit_dot.html cites ./one.rs:1 in range;
  // cit_dot_oob.html cites ./one.rs:99 — the H1 bypass form (old regex: no
  // head matched, exit 0 despite an out-of-range line).
  await writeFile(
    path.join(base, 'cit_dot.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>./one.rs:1</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'cit_dot_oob.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>./one.rs:99</code>.</p>', '</body></html>', ''].join('\n')
  )
  // M3 (adversarial round 5) — comma continuations and a < 1 start are
  // implemented behaviours that must not survive deletion.
  await writeFile(
    path.join(base, 'cit_cont_oob.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>one.rs:1,99</code>.</p>', '</body></html>', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'cit_zero.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>one.rs:0</code>.</p>', '</body></html>', ''].join('\n')
  )
  // M1 (adversarial round 5) — `recommendation` must not false-positive on a
  // legitimate identifier/path such as src/recommendation.rs.
  await writeFile(
    path.join(base, 'apparatus_recommend_path.html'),
    ['<!doctype html>', '<html><body>', '<p>See <code>src/recommendation.rs</code> for details.</p>', '</body></html>', ''].join('\n')
  )
  // R1 (this review) — plural `Recommendations` is a prose-only recommendation
  // form and must be rejected; the singular path guard above stays green.
  await writeFile(
    path.join(base, 'apparatus_recommend_plural.html'),
    ['<!doctype html>', '<html><body>', '<h2>Recommendations</h2>', '</body></html>', ''].join('\n')
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
  // M1 (round-4 advisory): the three cases that close check-5's negative-only
  // coverage. rowheader_short is the case a row-header reclassification (a <tr>
  // containing a <th> treated as a header row) would silently pass; asserting
  // "has 2 cells" also proves the row header was counted as a cell.
  expect('check5 tbody row header is a counted cell (rowheader_short)', ['rowheader_short.html'], 1, {
    has: ['table-cell-count', 'has 2 cells'],
  })
  expect('check5 correct tfoot row is accepted (tfoot_ok)', ['tfoot_ok.html'], 0, {
    has: ['HTML-CHECK-OK tfoot_ok.html'],
    no: ['HTML-STRUCT-FAIL'],
  })
  expect('check5 correct nested table is accepted (nested_ok)', ['nested_ok.html'], 0, {
    has: ['HTML-CHECK-OK nested_ok.html'],
    no: ['HTML-STRUCT-FAIL'],
  })

  expect('exit2 missing file: op-fail, no OK, clean 0', ['nope-missing.html'], 2, {
    has: ['HTML-CHECK-OP-FAIL', 'clean 0'],
    no: ['HTML-CHECK-OK'],
  })
  expect('exit2 colspan: op-fail, no OK, clean 0', ['colspan.html'], 2, {
    has: ['HTML-CHECK-OP-FAIL', 'not clean', 'clean 0'],
    no: ['HTML-CHECK-OK'],
  })

  // Check 6 — citation bounds: positive, negative and operational cases.
  // Every case asserts the exit code AND the marker it must emit (or must not
  // emit). The unreadable-cited-file case restores permissions before cleanup.
  expect('citation clean pass (exist + in range)', ['cite_ok.html'], 0, {
    has: ['HTML-CITATION-OK cite_ok.html (citations 1)', 'HTML-CHECK-OK cite_ok.html'],
    no: ['HTML-CITATION-FAIL', 'HTML-CITATION-OP-FAIL'],
  })
  expect('citation missing file names offender', ['cite_missing.html'], 1, {
    has: ['HTML-CITATION-FAIL cite_missing.html:3', 'missing-file', 'nope.rs:1'],
    no: ['HTML-CITATION-OK cite_missing.html', 'HTML-CHECK-OK'],
  })
  expect('citation out-of-range line', ['cite_out_of_range.html'], 1, {
    has: ['HTML-CITATION-FAIL cite_out_of_range.html:', 'out-of-range', 'one.rs:99', 'file has 1 line'],
    no: ['HTML-CITATION-OK cite_out_of_range.html', 'HTML-CHECK-OK'],
  })
  expect('citation malformed range (start > end)', ['cite_malformed.html'], 1, {
    has: ['HTML-CITATION-FAIL cite_malformed.html:', 'malformed-range', 'one.rs:5-2'],
    no: ['out-of-range', 'HTML-CITATION-OK', 'HTML-CHECK-OK'],
  })
  expect('citation unreadable cited file is operational (exit 2)', ['cite_locked.html'], 2, {
    has: ['HTML-CITATION-OP-FAIL cite_locked.html:', 'read-', 'locked.rs:1'],
    no: ['HTML-CITATION-FAIL', 'HTML-CITATION-OK cite_locked.html', 'HTML-CHECK-OK'],
  })
  await chmod(path.join(base, 'locked.rs'), 0o644)
  expect('citation src/ fallback resolution', ['cite_src.html'], 0, {
    has: ['HTML-CITATION-OK cite_src.html (citations 1)', 'HTML-CHECK-OK cite_src.html'],
    no: ['HTML-CITATION-FAIL', 'HTML-CITATION-OP-FAIL'],
  })
  // H1 (adversarial round 5): dot-prefixed heads are parsed and resolved after
  // stripping `./`. cit_dot_oob is the H1 regression — the old regex matched no
  // head, printed HTML-CITATION-OK and exited 0 despite the out-of-range line.
  expect('citation ./-prefixed head in range', ['cit_dot.html'], 0, {
    has: ['HTML-CITATION-OK cit_dot.html (citations 1)', 'HTML-CHECK-OK cit_dot.html'],
    no: ['HTML-CITATION-FAIL', 'HTML-CITATION-OP-FAIL'],
  })
  expect('citation ./-prefixed head out of range (H1 regression)', ['cit_dot_oob.html'], 1, {
    has: ['HTML-CITATION-FAIL cit_dot_oob.html:', 'out-of-range', 'one.rs:99', 'file has 1 line'],
    no: ['HTML-CITATION-OK cit_dot_oob.html', 'HTML-CHECK-OK'],
  })
  // M3 (adversarial round 5): comma continuations and start < 1 are proven.
  expect('citation ,NNN continuation out of range', ['cit_cont_oob.html'], 1, {
    has: ['HTML-CITATION-FAIL cit_cont_oob.html:', 'out-of-range', 'one.rs:99'],
    no: ['HTML-CITATION-OK cit_cont_oob.html', 'HTML-CHECK-OK'],
  })
  expect('citation start < 1 (file.rs:0) fails', ['cit_zero.html'], 1, {
    has: ['HTML-CITATION-FAIL cit_zero.html:', 'out-of-range', 'one.rs:0', 'file has 1 line'],
    no: ['HTML-CITATION-OK cit_zero.html', 'HTML-CHECK-OK'],
  })

  // Check 7 — banned issue apparatus: every offender named, and the legitimate
  // binary name `alumina-proxy` (plus the spec path) must never false-positive.
  expect('check7 banned apparatus: all offenders named', ['apparatus.html'], 1, {
    has: [
      'HTML-APPARATUS-FAIL apparatus.html:',
      'F-nn "F-01"',
      'U-nn "U-02"',
      'bead-id "alumina-abcde"',
      'S1-S2-S3 "(S1)"',
      'owner-decision "owner decision"',
      'review-finding "review finding"',
      'recommendation "recommendation"',
    ],
    no: ['HTML-APPARATUS-OK apparatus.html', 'HTML-CHECK-OK'],
  })
  expect('check7 apparatus false-positive guard (alumina-proxy clean)', ['apparatus_fp.html'], 0, {
    has: ['HTML-APPARATUS-OK apparatus_fp.html', 'HTML-CHECK-OK apparatus_fp.html'],
    no: ['HTML-APPARATUS-FAIL', 'HTML-CITATION-FAIL', 'HTML-CITATION-OP-FAIL'],
  })
  // M1 (adversarial round 5): `recommendation` inside a path/identifier must
  // not be flagged as bead-id-class apparatus.
  expect('check7 recommendation path false-positive guard (M1)', ['apparatus_recommend_path.html'], 0, {
    has: ['HTML-APPARATUS-OK apparatus_recommend_path.html', 'HTML-CHECK-OK apparatus_recommend_path.html'],
    no: ['HTML-APPARATUS-FAIL', 'HTML-CITATION-FAIL', 'HTML-CITATION-OP-FAIL'],
  })
  expect('check7 plural Recommendations rejected (R1)', ['apparatus_recommend_plural.html'], 1, {
    has: ['HTML-APPARATUS-FAIL apparatus_recommend_plural.html:', 'recommendation "Recommendations"'],
    no: ['HTML-APPARATUS-OK apparatus_recommend_plural.html', 'HTML-CHECK-OK'],
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
