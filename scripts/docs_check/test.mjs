#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { writeFile, mkdir, mkdtemp, rm, chmod } from 'node:fs/promises'
import path from 'node:path'

const repoRoot = process.cwd()
const checker = process.env.DOCS_CHECK_JS || path.join(repoRoot, 'scripts/docs_check/check.mjs')
const base = await mkdtemp(path.join(repoRoot, 'target', 'docsctl-'))
let failures = 0
let ran = 0

function expect(name, files, wantExit, opts) {
  ran++
  const res = spawnSync(process.execPath, [checker, ...files], { cwd: base, encoding: 'utf8' })
  const got = res.status
  const err = res.stderr || ''
  const out = res.stdout || ''
  const diag = !opts.diag || err.includes(opts.diag)
  const clean = (opts.noClean || []).every((s) => !out.includes(s))
  const has = !opts.hasOut || out.includes(opts.hasOut)
  const ok = got === wantExit && diag && clean && has
  if (!ok) {
    failures++
    console.error(
      `CTRL-FAIL ${name}: got exit ${got} (want ${wantExit}) diag=${diag} clean=${clean} has=${has}` +
        `\n  out: ${out.split('\n').filter(Boolean).join(' | ')}` +
        `\n  err: ${err.split('\n').filter(Boolean).join(' | ')}`
    )
  } else {
    console.log(`CTRL-PASS ${name} (exit ${got})`)
  }
}

try {
  await mkdir(path.join(base, 'odir'))
  await mkdir(path.join(base, 'sub'))
  await writeFile(path.join(base, 'odir', 'miss.md'), ['# Inside', ''].join('\n'))
  await chmod(path.join(base, 'odir'), 0o000)

  await writeFile(
    path.join(base, 'a.md'),
    [
      '# A doc',
      '## Protocol contract',
      '## Protocol contract',
      '| cell |',
      '| --- |',
      '| [cell](#protocol-contract) |',
      '[good](#protocol-contract)',
      '[dup-two](#protocol-contract-1)',
      '[top](#)',
      '[bad-case](#Protocol-Contract)',
      '[bad-hyphen](#protocol--contract)',
      '[over](#protocol-contract-2)',
      ''
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'c.md'),
    ['# C Plan', '### Slice 7 — Release gates + deployment readiness', '[same](#slice-7--release-gates--deployment-readiness)', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'b.md'),
    [
      '# B',
      '## 1. Section matrix (all `alumina.md` sections)',
      '[code-heading](#1-section-matrix-all-aluminamd-sections)',
      '[cross-ok](c.md#slice-7--release-gates--deployment-readiness)',
      ''
    ].join('\n')
  )
  await writeFile(
    path.join(base, 'b2.md'),
    [
      '# B2',
      '[cross-wrong-hyphen](c.md#slice-7-release-gates-deployment-readiness)',
      '[cross-wrong-case](c.md#Slice-7--Release-Gates--Deployment-Readiness)',
      '[cross-missing-frag](c.md#no-such-heading)',
      ''
    ].join('\n')
  )
  await writeFile(path.join(base, '`tick`.md'), ['# Tock', ''].join('\n'))
  await writeFile(path.join(base, "q'uote.md"), ['# Quote', ''].join('\n'))
  await writeFile(
    path.join(base, 'clean.md'),
    [
      '# Clean',
      '## Protocol contract',
      '## Protocol contract',
      '[one](#protocol-contract)',
      '[two](#protocol-contract-1)',
      '[tick](./%60tick%60.md)',
      "[ra](q'uote.md)",
      ''
    ].join('\n')
  )
  await writeFile(path.join(base, 'miss.md'), ['[absent](no-such-file.md)', ''].join('\n'))

  await writeFile(path.join(base, 'locked.md'), ['# Locked', ''].join('\n'))
  await chmod(path.join(base, 'locked.md'), 0o000)
  await writeFile(path.join(base, 'dir.md'), ['[dir](odir)', ''].join('\n'))
  await writeFile(path.join(base, 'unread.md'), ['[locked](locked.md)', ''].join('\n'))
  await writeFile(path.join(base, 'op2.md'), ['[data](data:text/plain,x)', '[mp](#bad%zz)', ''].join('\n'))
  await writeFile(path.join(base, 'eh.md'), ['# EH', '## protocol-contract', '[good](#protocol-contract)', '[eh](#protocol-contract#extra)', ''].join('\n'))
  await writeFile(path.join(base, 'mp2.md'), ['# MP2', '[pct](#foo100%)', ''].join('\n'))
  await writeFile(path.join(base, 'mp3.md'), ['# MP3', '[pctA](#foo100%A)', ''].join('\n'))
  await writeFile(path.join(base, 'h.md'), ['# H', '<a id="anchor-one"></a>', '[html](#anchor-one)', '[hdr](#h)', ''].join('\n'))
  await writeFile(path.join(base, 'fake.html'), ['# Fake', ''].join('\n'))
  await writeFile(path.join(base, 'htm.md'), ['# HTM', '[htmlt](fake.html#Fake)', ''].join('\n'))
  await writeFile(path.join(base, 'statf.md'), ['[s](odir/miss.md#x)', ''].join('\n'))

  // M4 citation resolution + range-check fixtures:
  // target files for citation checks (cwd-relative as-given, then src/, then tests/)
  await mkdir(path.join(base, 'src'), { recursive: true })
  await mkdir(path.join(base, 'tests'), { recursive: true })
  await writeFile(path.join(base, 'target.rs'), ['// 1', '// 2', '// 3', '// 4', '// 5', ''].join('\n')) // 5 lines
  await writeFile(path.join(base, 'src', 'fallback.rs'), ['// a', '// b', '// c', '// d', ''].join('\n')) // 4 lines
  await writeFile(path.join(base, 'tests', 'dfallback.rs'), ['// z', '// y', ''].join('\n')) // 2 lines
  await writeFile(
    path.join(base, 'cit_clean.md'),
    [
      'as-given `target.rs:1-5`, src fallback `fallback.rs:2-4`, tests fallback `dfallback.rs:1-2`',
      'comma continuation `target.rs:1-3,5` and `target.rs:1-3,4-5`',
      ''
    ].join('\n')
  )
  await writeFile(path.join(base, 'cit_missing.md'), ['missing file citation `ghost.rs:10`', ''].join('\n'))
  await writeFile(
    path.join(base, 'cit_range.md'),
    ['out-of-range `target.rs:9` and `target.rs:1-3,4-6`', ''].join('\n')
  )
  await writeFile(path.join(base, 'cit_bad.md'), ['start>end `target.rs:4-2`', ''].join('\n'))
  await writeFile(path.join(base, 'cit_locked.rs'), ['// x', ''].join('\n'))
  await chmod(path.join(base, 'cit_locked.rs'), 0o000)
  await writeFile(path.join(base, 'cit_op.md'), ['unreadable target `cit_locked.rs:1`', ''].join('\n'))

  await writeFile(
    path.join(base, 'ref.md'),
    ['[used][r]', '', '[r]: ok-doc.md#protocol-contract', '[r]: no-such-file.md', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'ok-doc.md'),
    ['# OK', '## Protocol contract', ''].join('\n')
  )
  await writeFile(
    path.join(base, 'refbad.md'),
    ['[gone][r]', '', '[r]: missing-file.md#x', ''].join('\n')
  )

  expect('clean-positive (duplicates, inline-code, inert path bytes)', ['clean.md', 'c.md', 'b.md'], 0, {})
  expect('ref first-definition win + unused duplicate def not a request', ['ref.md'], 0, {})
  expect('domain-fail literal fragments on duplicates', ['a.md'], 1, { diag: 'DOCSLINK-MISSING-FRAGMENT', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('domain-fail cross-file wrong hyphen/case/missing', ['b2.md', 'c.md'], 1, { diag: 'DOCSLINK-MISSING-FRAGMENT', noClean: ['DOCSLINK-CHECK-OK', 'DOCSLINK-OK b2.md'] })
  expect('domain-fail missing file', ['miss.md'], 1, { diag: 'DOCSLINK-MISSING', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('domain-fail used reference to missing target', ['refbad.md'], 1, { diag: 'DOCSLINK-MISSING', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail stat error (EACCES via unsearchable parent)', ['statf.md'], 2, { diag: 'DOCSLINK-OP-FAIL', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail directory target', ['dir.md'], 2, { diag: 'DOCSLINK-OP-FAIL', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail unreadable target (read EACCES)', ['unread.md'], 2, { diag: 'DOCSLINK-OP-FAIL', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail unsupported scheme + malformed percent', ['op2.md'], 2, { diag: 'DOCSLINK-OP-FAIL', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail trailing short percent % at end', ['mp2.md'], 2, { diag: 'malformed-percent', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail short percent escape %A at end', ['mp3.md'], 2, { diag: 'malformed-percent', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('domain-fail extra# fragment keeps full remainder (no truncation)', ['eh.md'], 1, { diag: 'DOCSLINK-MISSING-FRAGMENT', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail html anchor unsupported', ['h.md'], 2, { diag: 'html-anchor-unsupported', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('op-fail non-Markdown fragment target no fabricated heading', ['htm.md'], 2, { diag: 'unsupported-target', noClean: ['DOCSLINK-OK', 'DOCSLINK-CHECK-OK'] })

  // M4 citation resolution + range-check cases
  expect('citation-clean as-given/src/tests resolution + comma continuation', ['cit_clean.md'], 0, { hasOut: 'CITATION-CHECK-OK', noClean: ['CITATION-CHECK-RESULT'] })
  expect('citation-missing file fails closed naming the citation', ['cit_missing.md'], 1, { diag: 'CITATION-MISSING', noClean: ['CITATION-CHECK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('citation-line out-of-range fails closed naming line count', ['cit_range.md'], 1, { diag: 'CITATION-LINE-RANGE', noClean: ['CITATION-CHECK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('citation-start>end malformed fails closed', ['cit_bad.md'], 1, { diag: 'CITATION-MALFORMED', noClean: ['CITATION-CHECK-OK', 'DOCSLINK-CHECK-OK'] })
  expect('citation-unreadable target is op-fail (exit 2) never PASS', ['cit_op.md'], 2, { diag: 'CITATION-OP-FAIL', noClean: ['CITATION-CHECK-OK', 'DOCSLINK-CHECK-OK'] })

  const staticRes = spawnSync('rg', ['-n', 'child_process|execSync|spawn|new Function|node:http|node:https', checker], { encoding: 'utf8' })
  ran++
  if (staticRes.status === 1) {
    console.log('CTRL-PASS static-no-exec (rg no-match, exit 1)')
  } else if (staticRes.status === 0) {
    failures++
    console.error(`CTRL-FAIL static-no-exec: adapter source contains runtime exec/network imports:\n${staticRes.stdout}`)
  } else {
    failures++
    console.error(`CTRL-FAIL static-no-exec: rg producer error status ${staticRes.status} (exit 0 was blocked; a search error cannot pass)`)
  }
} finally {
  try {
    await chmod(path.join(base, 'odir'), 0o755)
  } catch {}
  try {
    await chmod(path.join(base, 'locked.md'), 0o644)
  } catch {}
  try {
    await chmod(path.join(base, 'cit_locked.rs'), 0o644)
  } catch {}
  await rm(base, { recursive: true, force: true })
}

if (failures > 0) {
  console.error(`DOCS-CTRL-FAIL (${failures}/${ran} control groups failed)`)
  process.exit(1)
}
console.log(`DOCS-CTRL-PASS (${ran} groups)`)
process.exit(0)
