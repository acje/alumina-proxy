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
//   5. table cell-count consistency: every <tr> in <tbody> has the same
//      cell count as the <th> header row; a <table> with no <thead> fails
//
// Exit discipline (one-way split — operational never folds into 0/1):
//   0  every input clean
//   1  at least one structural check failure (all offenders named)
//   2  operational/unsupported only (missing/unreadable file, colspan/
//      rowspan). A run with both a failure and an operation exits 2 but
//      still prints every HTML-STRUCT-FAIL line it found.
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'])
const RAWTEXT = new Set(['style', 'script'])
const CELLS = new Set(['td', 'th'])

const files = process.argv.slice(2)
const root = process.cwd()

let opsTotal = 0
let structTotal = 0
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
  const local = { ops: 0, struct: 0 }
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
        } else if (top.headerCount !== null) {
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
      opFail(`${f}:${lineNo} unsupported colspan/rowspan on <${tag.name}> (cell-count cannot be verified)`)
    }
    if (tag.selfClosing || VOID.has(tag.name)) continue

    let trRole = null
    let tableRef = null
    if (tag.name === 'tr') {
      const top0 = stack[stack.length - 1]
      if (top0 && (top0.name === 'thead' || top0.name === 'tbody')) trRole = top0.name === 'thead' ? 'header' : 'body'
      tableRef = nearestAncestor((fr) => fr.isTable)
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

  return { ids: ids.size, fragments: frags.length, tables: tableCount, figures: figureCount, clean: local.ops === 0 && local.struct === 0 }
}

function opFail(detail) {
  opsTotal++
  lines.push(`HTML-CHECK-OP-FAIL ${detail}`)
}

if (files.length === 0) {
  opFail('no input files (fixed nonempty root list required)')
  lines.push('HTML-CHECK-RESULT (files 0, clean 0, ids 0, fragments 0, tables 0, figures 0)')
  process.stdout.write(`${lines.join('\n')}\n`)
  process.exit(2)
}

for (const f of files) {
  const res = await checkOne(f)
  if (!res) continue
  if (res.clean) {
    cleanTotal++
    lines.push(`HTML-CHECK-OK ${f} (ids ${res.ids}, fragments ${res.fragments}, tables ${res.tables}, figures ${res.figures})`)
  }
  idsTotal += res.ids
  fragsTotal += res.fragments
  tablesTotal += res.tables
  figuresTotal += res.figures
}
lines.push(`HTML-CHECK-RESULT (files ${files.length}, clean ${cleanTotal}, ids ${idsTotal}, fragments ${fragsTotal}, tables ${tablesTotal}, figures ${figuresTotal})`)
process.stdout.write(`${lines.join('\n')}\n`)

if (opsTotal > 0) process.exit(2)
if (structTotal > 0) process.exit(1)
process.exit(0)
