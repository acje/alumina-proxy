#!/usr/bin/env node
// Structural HTML gate for the docs corpus. Node builtins only
// (node:fs, node:path, node:process): no npm dependency, no package.json, no
// network. docslink_check's Markdown parser answers html-anchor-unsupported
// for HTML, so HTML artefacts get their own structural gate (verify.sh
// html_structure_check). Inputs are a fixed nonempty argv list of filesystem
// paths; never shell.
//
// Checks (each finding names file:line):
//   1. well-formedness: tag balance, no stray close, exactly one root
//      element and <html> is that root
//   2. duplicate id="..." values
//   3. internal fragment closure: every href="#frag" resolves to an
//      id="frag" or name="frag" in the same document
//   4. every <figure> contains a <desc> (a <desc> outside a figure is not
//      required and never fails)
//   5. table cell-count consistency: every <tr> inside a <table> (in <thead>,
//      <tbody>, <tfoot>, or directly under <table>) has the same cell count as
//      the <th> header row; a <table> with no <thead>, or a <thead> with no
//      header cell row, fails (table-header-missing)
//   6. citation bounds: every `<file>:LINE[-LINE]` whose file head matches
//      ((?:\.{1,2}/)*[A-Za-z0-9_][A-Za-z0-9_./-]*\.(rs|md|toml|sh|mjs|json|
//      html)), rejected when preceded by [A-Za-z0-9_./-], must resolve
//      as-given against the working directory, then src/, then tests/. A
//      leading `./` prefix is accepted and normalised away before resolution
//      (the natural `rg -n PATTERN ./src` copy-paste form); `../` is resolved
//      as-given through the same candidate order, so an escaping path fails to
//      resolve and is reported. Every cited range must satisfy
//      1 <= start <= end <= lineCount. A missing file, a malformed
//      range (start > end) and an out-of-range line are check failures;
//      stat/read errors other than ENOENT are operational. Bare `:NNN`
//      continuations (no leading file name, e.g. `:1040-1042`, `:443`) are
//      NOT independently checked — they inherit an implicit file from
//      surrounding prose and would false-positive on prose like
//      `https://host:443` (residual, documented, matching the docs-check
//      convention).
//   7. banned issue apparatus: F-NN, U-NN, bead ids `alumina-xxxxx`
//      (the negative lookahead keeps the legitimate `alumina-proxy` binary
//      name clean), severity tags `(S1)`/`(S2)`/`(S3)`, and the phrases
//      `owner decision`, `review finding`, and prose-only `recommendation`
//      (case-insensitive; identifier/path forms like `src/recommendation.rs`
//      are clean). Any occurrence is a check failure. The class set is a
//      fixed, intentionally narrow contract (two-digit F-NN / U-NN, five-char
//      `alumina-xxxxx` bead ids, S1-S3, the three phrases): variants outside
//      these exact classes are not scanned. The scan covers the whole file
//      including raw markup, so the set is a heuristic, not a proof of
//      semantic apparatus (residual, documented).
//
// Exit discipline (one-way split — operational never folds into 0/1):
//   0  every input clean
//   1  at least one structural, citation-bounds or issue-apparatus check
//      failure (all offenders named)
//   2  operational/unsupported only (missing/unreadable input file, colspan/
//      rowspan, or an unreadable cited file). A run with both a failure and an
//      operation exits 2 but still prints every check-failure line it found.
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'])
const RAWTEXT = new Set(['style', 'script'])
const CELLS = new Set(['td', 'th'])

// Check 6 — citation head and continuation. The head requires a file carrying
// one of the corpus extensions immediately followed by :LINE[-LINE]; a
// preceding [A-Za-z0-9_./-] rejects the match, so a bare `:NNN` continuation
// or a `host:443` port never acquires an implicit file. An optional `./` or
// `../` prefix is part of the head and `./` is stripped before resolution.
// `,NNN` / `,NNN-NNN` continuations extend the same cited file (docs-check
// convention).
const CIT_HEAD_RE = /(^|[^A-Za-z0-9_./-])((?:\.{1,2}\/)*[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:rs|md|toml|sh|mjs|json|html)):([0-9]+)(?:-([0-9]+))?/g
const CIT_CONT_RE = /^,([0-9]+)(?:-([0-9]+))?/

// Check 7 — banned issue apparatus. Each entry labels the pattern class so the
// failure line names the class as well as the matched text.
const APPARATUS_RE = [
  { label: 'F-nn', re: /\bF-\d{2}\b/g },
  { label: 'U-nn', re: /\bU-\d{2}\b/g },
  { label: 'bead-id', re: /\balumina-(?!proxy\b)[a-z0-9]{5}\b/g },
  { label: 'S1-S2-S3', re: /\((?:S1|S2|S3)\)/g },
  { label: 'owner-decision', re: /owner decision/gi },
  { label: 'review-finding', re: /review finding/gi },
  { label: 'recommendation', re: /(?<![A-Za-z0-9_./-])recommendation(?![A-Za-z0-9_/-])/gi },
]

const citLineCache = new Map()

const files = process.argv.slice(2)
const root = process.cwd()

let opsTotal = 0
let structTotal = 0
let citHeadsTotal = 0
let citFailTotal = 0
let citOpsTotal = 0
let apparatusTotal = 0
let cleanTotal = 0
let idsTotal = 0
let fragsTotal = 0
let tablesTotal = 0
let figuresTotal = 0
const lines = []

const WS = /[\s]/
const NAME_CH = /[A-Za-z0-9:_-]/

// Parse attribute name=value pairs from the region [from, to) of a single
// tag body (to excludes the terminating '>'). Quoted values may contain '<'
// or '>'; the region was bounded by a quote-aware scan so those never leak.
function collectAttrs(text, from, to, attrs) {
  let i = from
  while (i < to) {
    while (i < to && WS.test(text[i])) i++
    if (i >= to) break
    const ns = i
    while (i < to && !/[\s=/>]/.test(text[i])) i++
    const aname = text.slice(ns, i).toLowerCase()
    if (!aname) { i++; continue }
    while (i < to && WS.test(text[i])) i++
    let value = ''
    if (i < to && text[i] === '=') {
      i++
      while (i < to && WS.test(text[i])) i++
      if (i < to && (text[i] === '"' || text[i] === "'")) {
        const q = text[i]
        i++
        const vs = i
        while (i < to && text[i] !== q) i++
        value = text.slice(vs, i)
        if (i < to) i++
      } else {
        const vs = i
        while (i < to && !/[\s>]/.test(text[i])) i++
        value = text.slice(vs, i)
      }
    }
    if (!(aname in attrs)) attrs[aname] = value
  }
}

// Read one tag token at text[start] === '<'. Returns null when the '<' is
// not a real tag (no terminating '>' or no tag name) so the caller treats
// it as text.
function readTag(text, start) {
  const n = text.length
  let i = start + 1
  const isClose = text[i] === '/'
  if (isClose) i++
  const nameStart = i
  while (i < n && NAME_CH.test(text[i])) i++
  const nameEnd = i
  const name = text.slice(nameStart, nameEnd).toLowerCase()
  if (!/^[a-z]/.test(name)) return null
  let quote = null
  let end = -1
  for (; i < n; i++) {
    const c = text[i]
    if (quote !== null) {
      if (c === quote) quote = null
      continue
    }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === '>') { end = i; break }
  }
  if (end === -1) return null
  let selfClosing = false
  if (!isClose) {
    let j = end - 1
    while (j >= nameEnd && WS.test(text[j])) j--
    selfClosing = text[j] === '/'
  }
  const attrs = {}
  collectAttrs(text, nameEnd, end, attrs)
  return { isClose, name, attrs, selfClosing, start, end }
}

async function checkOne(f) {
  const abs = path.resolve(root, f)
  let st
  try {
    st = await stat(abs)
  } catch (err) {
    opFail(`${f} missing (${err.code || 'stat'})`)
    return null
  }
  if (!st.isFile()) {
    opFail(`${f} non-regular (not a regular file)`)
    return null
  }
  let text
  try {
    text = await readFile(abs, 'utf8')
  } catch (err) {
    opFail(`${f} unreadable (${err.code || 'read'})`)
    return null
  }
  const local = { ops: 0, struct: 0, citHeads: 0, citFail: 0, citOps: 0, apparatus: 0 }
  const sf = (lineNo, kind, detail) => { local.struct++; structTotal++; lines.push(`HTML-STRUCT-FAIL ${f}:${lineNo} ${kind} ${detail}`) }

  const n = text.length
  const lineStarts = [0]
  for (let k = 0; k < n; k++) if (text.charCodeAt(k) === 10) lineStarts.push(k + 1)
  const lineAt = (off) => {
    let lo = 0
    let hi = lineStarts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (lineStarts[mid] <= off) lo = mid
      else hi = mid - 1
    }
    return lo + 1
  }

  // Checks 6 and 7 operate on the document text alone (they share the
  // structural line index for `:line` attribution); the tag walk below owns the
  // structural checks 1-5.
  await checkCitationsIn(f, text, lineAt, local)
  checkApparatusIn(f, text, lineAt, local)

  const ids = new Map()
  const names = new Set()
  const frags = []
  const stack = []
  let roots = 0
  let rootName = ''
  let rootLine = 1
  let figureCount = 0
  let tableCount = 0

  const nearestAncestor = (pred) => {
    for (let k = stack.length - 1; k >= 0; k--) if (pred(stack[k])) return stack[k]
    return null
  }

  let i = 0
  while (i < n) {
    const lt = text.indexOf('<', i)
    if (lt === -1) break
    i = lt
    if (text.startsWith('<!--', i)) {
      const ce = text.indexOf('-->', i + 4)
      i = ce === -1 ? n : ce + 3
      continue
    }
    const two = text.slice(i + 1, i + 3)
    if (two === '!' || two === '?') {
      let j = i + 2
      let q = null
      let end = -1
      for (; j < n; j++) {
        const c = text[j]
        if (q !== null) { if (c === q) q = null; continue }
        if (c === '"' || c === "'") { q = c; continue }
        if (c === '>') { end = j; break }
      }
      i = end === -1 ? n : end + 1
      continue
    }
    const tag = readTag(text, i)
    if (!tag) { i++; continue }
    i = tag.end
    const lineNo = lineAt(tag.start)

    if (tag.isClose) {
      if (stack.length === 0) {
        sf(lineNo, 'stray-close', `</${tag.name}> with no matching open element`)
        continue
      }
      const top = stack[stack.length - 1]
      if (top.name !== tag.name) {
        sf(lineNo, 'tag-mismatch', `expected </${top.name}> got </${tag.name}>`)
        stack.pop()
        continue
      }
      stack.pop()
      if (top.name === 'tr' && top.tableRef) {
        if (top.trRole === 'header' && top.tableRef.headerCount === null) top.tableRef.headerCount = top.cells
        else if (top.trRole === 'body') top.tableRef.bodyRows.push({ cells: top.cells, line: lineNo })
      }
      if (top.isFigure && !top.descSeen) sf(top.line, 'missing-desc', 'figure contains no <desc> element')
      if (top.isTable) {
        if (!top.foundThead) {
          sf(top.line, 'table-header-missing', 'table has no <thead> header row')
        } else if (top.headerCount === null) {
          sf(top.line, 'table-header-missing', 'table <thead> has no header cell row')
        } else {
          for (const row of top.bodyRows) {
            if (row.cells !== top.headerCount) {
              sf(row.line, 'table-cell-count', `tbody row has ${row.cells} cells, header row has ${top.headerCount}`)
            }
          }
        }
      }
      continue
    }

    const attrs = tag.attrs
    if (Object.prototype.hasOwnProperty.call(attrs, 'id')) {
      if (!ids.has(attrs.id)) ids.set(attrs.id, [])
      ids.get(attrs.id).push(lineNo)
    }
    if (Object.prototype.hasOwnProperty.call(attrs, 'name')) names.add(attrs.name)
    if (tag.name === 'a' && Object.prototype.hasOwnProperty.call(attrs, 'href') && attrs.href.startsWith('#')) {
      frags.push({ value: attrs.href.slice(1), line: lineNo })
    }
    if (CELLS.has(tag.name) &&
        (Object.prototype.hasOwnProperty.call(attrs, 'colspan') || Object.prototype.hasOwnProperty.call(attrs, 'rowspan'))) {
      opFail(`${f}:${lineNo} unsupported colspan/rowspan on <${tag.name}> (cell-count cannot be verified)`, local)
    }
    if (tag.selfClosing || VOID.has(tag.name)) continue

    let trRole = null
    let tableRef = null
    if (tag.name === 'tr') {
      const top0 = stack[stack.length - 1]
      tableRef = nearestAncestor((fr) => fr.isTable)
      trRole = (tableRef && top0 && top0.name === 'thead') ? 'header' : 'body'
    } else if (tag.name === 'thead' || tag.name === 'tbody') {
      tableRef = nearestAncestor((fr) => fr.isTable)
    }

    if (tag.name === 'figure') figureCount++
    if (tag.name === 'table') tableCount++
    if (tag.name === 'desc') {
      const fig = nearestAncestor((fr) => fr.isFigure)
      if (fig) fig.descSeen = true
    }

    const frame = {
      name: tag.name,
      line: lineNo,
      isFigure: tag.name === 'figure',
      descSeen: false,
      isTable: tag.name === 'table',
      foundThead: false,
      headerCount: null,
      bodyRows: [],
      trRole,
      tableRef,
      cells: 0,
    }
    if (tag.name === 'thead' && tableRef) tableRef.foundThead = true
    if (CELLS.has(tag.name)) {
      const tr = nearestAncestor((fr) => fr.name === 'tr')
      if (tr) tr.cells++
    }
    if (stack.length === 0) { roots++; rootName = tag.name; rootLine = lineNo }
    stack.push(frame)
    if (RAWTEXT.has(tag.name)) {
      const closeIdx = text.toLowerCase().indexOf(`</${tag.name}`, i)
      i = closeIdx === -1 ? n : closeIdx
    }
  }

  for (let k = stack.length - 1; k >= 0; k--) {
    sf(stack[k].line, 'unclosed-element', `open <${stack[k].name}> never closed`)
  }
  if (roots !== 1) {
    sf(rootLine, 'root-count', roots === 0 ? 'no root element found' : `found ${roots} root elements, expected exactly one`)
  } else if (rootName !== 'html') {
    sf(rootLine, 'root-count', `root element is <${rootName}>, expected <html>`)
  }
  for (const [v, locs] of ids) {
    if (locs.length > 1) sf(locs[0], 'duplicate-id', `id="${v}" reused on lines ${locs.slice(1).join(', ')}`)
  }
  for (const fr of frags) {
    if (!ids.has(fr.value) && !names.has(fr.value)) {
      sf(fr.line, 'dangling-fragment', `href="#${fr.value}" has no matching id= or name= target`)
    }
  }

  if (local.citFail === 0 && local.citOps === 0) {
    lines.push(`HTML-CITATION-OK ${f} (citations ${local.citHeads})`)
  }
  if (local.apparatus === 0) {
    lines.push(`HTML-APPARATUS-OK ${f}`)
  }

  return {
    ids: ids.size,
    fragments: frags.length,
    tables: tableCount,
    figures: figureCount,
    ops: local.ops,
    struct: local.struct,
    clean: local.ops === 0 && local.struct === 0 && local.citFail === 0 && local.citOps === 0 && local.apparatus === 0,
  }
}

function opFail(detail, local) {
  opsTotal++
  if (local) local.ops++
  lines.push(`HTML-CHECK-OP-FAIL ${detail}`)
}

function lineCountOf(text) {
  if (text.length === 0) return 0
  return text.split('\n').length - (text.endsWith('\n') ? 1 : 0)
}

// Resolve a cited file as-given against the working directory, then src/, then
// tests/ (docs-check convention). A stat error other than ENOENT is an
// operational result, never a verdict.
async function resolveCitationFile(file) {
  for (const cand of [file, `src/${file}`, `tests/${file}`]) {
    const abs = path.resolve(root, cand)
    try {
      const st = await stat(abs)
      if (st.isFile()) return { abs, resolved: cand }
    } catch (err) {
      if (err.code !== 'ENOENT') return { op: true, why: err.code || 'stat' }
    }
  }
  return null
}

// Check 6 — every citation head resolves and every cited range is well-formed
// and in bounds. Missing file / malformed range / out-of-range are check
// failures; a stat/read error other than ENOENT is operational. All offenders
// are named: the loop keeps scanning after the first defect.
async function checkCitationsIn(f, text, lineAt, local) {
  for (const m of text.matchAll(CIT_HEAD_RE)) {
    const docLine = lineAt(m.index)
    local.citHeads++
    citHeadsTotal++
    const file = m[2].replace(/^\.\//, '')
    const ranges = [{ start: Number(m[3]), end: m[4] ? Number(m[4]) : Number(m[3]) }]
    let from = m.index + m[0].length
    for (;;) {
      const cm = CIT_CONT_RE.exec(text.slice(from))
      if (!cm) break
      ranges.push({ start: Number(cm[1]), end: cm[2] ? Number(cm[2]) : Number(cm[1]) })
      from += cm[0].length
    }
    const head = ranges[0]
    const headStr = head.end === head.start ? `${file}:${head.start}` : `${file}:${head.start}-${head.end}`
    const resolved = await resolveCitationFile(file)
    if (!resolved) {
      local.citFail++
      citFailTotal++
      lines.push(`HTML-CITATION-FAIL ${f}:${docLine} missing-file ${headStr}`)
      continue
    }
    if (resolved.op) {
      local.citOps++
      citOpsTotal++
      lines.push(`HTML-CITATION-OP-FAIL ${f}:${docLine} stat-${resolved.why} ${headStr}`)
      continue
    }
    let lc = citLineCache.get(resolved.abs)
    if (lc === undefined) {
      try {
        lc = { ok: true, lines: lineCountOf(await readFile(resolved.abs, 'utf8')) }
      } catch (err) {
        lc = { ok: false, why: err.code || 'read' }
      }
      citLineCache.set(resolved.abs, lc)
    }
    if (!lc.ok) {
      local.citOps++
      citOpsTotal++
      lines.push(`HTML-CITATION-OP-FAIL ${f}:${docLine} read-${lc.why} ${headStr}`)
      continue
    }
    for (const r of ranges) {
      if (r.start > r.end) {
        local.citFail++
        citFailTotal++
        lines.push(`HTML-CITATION-FAIL ${f}:${docLine} malformed-range ${file}:${r.start}-${r.end}`)
        continue
      }
      if (r.start < 1 || r.end > lc.lines) {
        local.citFail++
        citFailTotal++
        lines.push(`HTML-CITATION-FAIL ${f}:${docLine} out-of-range ${file}:${r.start}-${r.end} (file has ${lc.lines} lines)`)
      }
    }
  }
}

// Check 7 — banned issue apparatus. Every match names the pattern class and
// the matched text, and counts as a check failure.
function checkApparatusIn(f, text, lineAt, local) {
  for (const pat of APPARATUS_RE) {
    pat.re.lastIndex = 0
    for (const m of text.matchAll(pat.re)) {
      local.apparatus++
      apparatusTotal++
      lines.push(`HTML-APPARATUS-FAIL ${f}:${lineAt(m.index)} ${pat.label} "${m[0]}"`)
    }
  }
}

if (files.length === 0) {
  opFail('no input files (fixed nonempty root list required)')
  lines.push('HTML-CHECK-RESULT (files 0, clean 0, ids 0, fragments 0, tables 0, figures 0, citations 0, apparatus 0)')
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(2)
}

for (const f of files) {
  const res = await checkOne(f)
  if (!res) continue
  if (res.clean) {
    cleanTotal++
    lines.push(`HTML-CHECK-OK ${f} (ids ${res.ids}, fragments ${res.fragments}, tables ${res.tables}, figures ${res.figures})`)
  } else if (res.ops > 0) {
    lines.push(`HTML-CHECK-OP-FAIL ${f} (not clean: ${res.ops} operational, ${res.struct} structural)`)
  }
  idsTotal += res.ids
  fragsTotal += res.fragments
  tablesTotal += res.tables
  figuresTotal += res.figures
}
lines.push(`HTML-CHECK-RESULT (files ${files.length}, clean ${cleanTotal}, ids ${idsTotal}, fragments ${fragsTotal}, tables ${tablesTotal}, figures ${figuresTotal}, citations ${citHeadsTotal}, apparatus ${apparatusTotal})`)
process.stdout.write(`${lines.join('\n')}\n`)

if (opsTotal > 0 || citOpsTotal > 0) process.exit(2)
if (structTotal > 0 || citFailTotal > 0 || apparatusTotal > 0) process.exit(1)
process.exit(0)
