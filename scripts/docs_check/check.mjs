#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { fromMarkdown } from 'mdast-util-from-markdown'
import { toString } from 'mdast-util-to-string'
import GithubSlugger from 'github-slugger'

const EXTERNAL = new Set(['http:', 'https:', 'mailto:'])
const files = process.argv.slice(2)
const root = process.cwd()
let domain = false, ops = false, localChecks = 0, outOfScope = 0

function walk(node, visit) {
  if (!node || typeof node !== 'object') return
  if (visit(node)) return
  if (Array.isArray(node.children)) node.children.forEach((child) => walk(child, visit))
}

function badPercent(value) {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) === 0x25 && (i + 2 >= value.length || !/^[0-9A-Fa-f]{2}$/.test(value.slice(i + 1, i + 3)))) return true
  }
  return false
}

function schemeOf(url) {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:/.exec(url)
  return !m ? 'local' : EXTERNAL.has(url.slice(0, m[0].length)) ? 'external' : 'unsupported'
}

function buildIndex(tree) {
  const slugger = new GithubSlugger()
  const defs = new Map()
  const slugs = new Set()
  const links = []
  let html = false
  walk(tree, (node) => {
    if (node.type === 'heading') {
      slugs.add(slugger.slug(toString(node, { includeHtml: false, includeImageAlt: false })))
    } else if (node.type === 'definition') {
      if (!defs.has(node.identifier)) defs.set(node.identifier, node.url)
    } else if (node.type === 'html') {
      html = true
    }
    return false
  })
  walk(tree, (node) => {
    if (node.type === 'linkReference' || node.type === 'imageReference') {
      if (defs.has(node.identifier)) links.push(defs.get(node.identifier))
    } else if ((node.type === 'link' || node.type === 'image') && node.url) {
      links.push(node.url)
    }
    return false
  })
  return { slugs, links, html }
}

async function load(abs) {
  let st
  try {
    st = await stat(abs)
  } catch (err) {
    return err.code === 'ENOENT' ? { kind: 'missing' } : { kind: 'op', why: err.code || 'stat' }
  }
  if (!st.isFile()) return { kind: 'op', why: 'nonregular' }
  try {
    const text = await readFile(abs, 'utf8')
    return { kind: 'ok', text, index: buildIndex(fromMarkdown(text)) }
  } catch (err) {
    return { kind: 'op', why: err.code || 'parse' }
  }
}

function fail(marker, detail) {
  if (marker === 'DOCSLINK-OP-FAIL') ops = true
  else domain = true
  process.stderr.write(`${marker} ${detail}\n`)
  return true
}

// M4: file:line citation resolution + range check. The docs corpus cites
// source lines as `<file>(.rs|.md):LINE[-LINE][,LINE[-LINE]]` in prose. We
// prove the cited file resolves (as-given, then src/, then tests/) and that
// every cited line exists. This is a line-existence proof only — it never
// claims the line still means what the sentence says. Bare `:NNN` continuations
// (no leading file name, e.g. `:1040-1042`, `:443`) are NOT independently
// checked — they inherit an implicit file from surrounding prose and would
// false-positive on prose like `https://host:443` (residual, documented).
let citOps = false
let citDomain = false
let citTotal = 0
const CIT_HEAD_RE = /(^|[^A-Za-z0-9_./-])([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:rs|md)):([0-9]+)(?:-([0-9]+))?/g
const CIT_CONT_RE = /^,([0-9]+)(?:-([0-9]+))?/
const citLineCache = new Map()

function lineCountOf(text) {
  if (text.length === 0) return 0
  return text.split('\n').length - (text.endsWith('\n') ? 1 : 0)
}

function citFail(marker, detail) {
  if (marker === 'CITATION-OP-FAIL') citOps = true
  else citDomain = true
  process.stderr.write(`${marker} ${detail}\n`)
  return true
}

async function resolveCitationFile(file) {
  for (const cand of [file, `src/${file}`, `tests/${file}`]) {
    const abs = path.resolve(root, cand)
    try {
      const st = await stat(abs)
      if (st.isFile()) return { abs, resolved: cand }
    } catch (err) {
      if (err.code !== 'ENOENT') return { op: true, why: err.code || 'stat', abs }
    }
  }
  return null
}

async function citationLineCount(abs) {
  if (citLineCache.has(abs)) return citLineCache.get(abs)
  try {
    const text = await readFile(abs, 'utf8')
    const value = { ok: true, lines: lineCountOf(text) }
    citLineCache.set(abs, value)
    return value
  } catch (err) {
    const value = { ok: false, why: err.code || 'read' }
    citLineCache.set(abs, value)
    return value
  }
}

async function checkCitationRanges(relFile, file, ranges) {
  const resolved = await resolveCitationFile(file)
  if (!resolved) return citFail('CITATION-MISSING', `${relFile} ${file}`)
  if (resolved.op) return citFail('CITATION-OP-FAIL', `${relFile} ${resolved.why} ${file}`)
  const lc = await citationLineCount(resolved.abs)
  if (!lc.ok) return citFail('CITATION-OP-FAIL', `${relFile} ${lc.why} ${file}`)
  for (const r of ranges) {
    if (r.start > r.end) return citFail('CITATION-MALFORMED', `${relFile} ${file}:${r.start}-${r.end}`)
    if (r.start < 1 || r.end > lc.lines) {
      return citFail('CITATION-LINE-RANGE', `${relFile} ${file}:${r.start}-${r.end} (file has ${lc.lines} lines)`)
    }
  }
  return false
}

async function checkCitations(relFile, text) {
  for (const m of text.matchAll(CIT_HEAD_RE)) {
    const file = m[2]
    citTotal++
    const ranges = [{ start: Number(m[3]), end: m[4] ? Number(m[4]) : Number(m[3]) }]
    let from = m.index + m[0].length
    for (;;) {
      const cm = CIT_CONT_RE.exec(text.slice(from))
      if (!cm) break
      ranges.push({ start: Number(cm[1]), end: cm[2] ? Number(cm[2]) : Number(cm[1]) })
      from += cm[0].length
    }
    if (await checkCitationRanges(relFile, file, ranges)) return true
  }
  return false
}

async function validate(thisDoc, url, srcAbs) {
  const scheme = schemeOf(url)
  if (scheme === 'external') {
    outOfScope++
    process.stdout.write(`OUT-OF-SCOPE-EXTERNAL ${thisDoc} ${url}\n`)
    return false
  }
  if (scheme === 'unsupported') return fail('DOCSLINK-OP-FAIL', `${thisDoc} unsupported-scheme ${url}`)
  if (badPercent(url)) return fail('DOCSLINK-OP-FAIL', `${thisDoc} malformed-percent ${url}`)
  const rawPath = url.split('#')[0]
  const fragment = url.includes('#') ? url.slice(url.indexOf('#') + 1) : ''
  let decoded
  try { decoded = decodeURIComponent(rawPath) } catch {
    return fail('DOCSLINK-OP-FAIL', `${thisDoc} malformed-percent ${url}`)
  }
  const tgt = rawPath === '' ? srcAbs : path.resolve(path.dirname(srcAbs), decoded)
  const probe = await load(tgt)
  if (probe.kind === 'missing') return fail('DOCSLINK-MISSING', `${thisDoc} ${tgt}`)
  if (probe.kind === 'op') return fail('DOCSLINK-OP-FAIL', `${thisDoc} ${probe.why} ${tgt}`)
  if (fragment === '') {
    localChecks++
    return false
  }
  if (tgt !== srcAbs && !/\.md$/i.test(decoded)) return fail('DOCSLINK-OP-FAIL', `${thisDoc} unsupported-target ${url}`)
  const index = probe.index
  if (index.slugs.has(fragment)) {
    localChecks++
    return false
  }
  return index.html
    ? fail('DOCSLINK-OP-FAIL', `${thisDoc} html-anchor-unsupported ${url}`)
    : fail('DOCSLINK-MISSING-FRAGMENT', `${thisDoc} ${url}`)
}

let cleanDocs = 0
for (const f of files) {
  const abs = path.resolve(root, f)
  const probe = await load(abs)
  if (probe.kind === 'missing') { fail('DOCSLINK-MISSING', `${f} ${abs}`); continue }
  if (probe.kind === 'op') { fail('DOCSLINK-OP-FAIL', `${f} ${probe.why} ${abs}`); continue }
  const index = probe.index
  let failed = false
  for (const url of index.links) if (await validate(f, url, abs)) failed = true
  if (await checkCitations(f, probe.text)) failed = true
  if (!failed) {
    cleanDocs++
    process.stdout.write(`DOCSLINK-OK ${f} (slugs ${index.slugs.size}, links ${index.links.length})\n`)
  }
}
const summary = `(files ${files.length}, clean ${cleanDocs}, local-checks ${localChecks}, out-of-scope ${outOfScope})`
const citSummary = `(citations ${citTotal}, roots ${files.length})`
if (ops || citOps) {
  process.stdout.write(`DOCSLINK-CHECK-RESULT ${summary}\n`)
  process.stdout.write(`CITATION-CHECK-RESULT ${citSummary}\n`)
  process.exit(2)
}
if (domain || citDomain) {
  process.stdout.write(`DOCSLINK-CHECK-RESULT ${summary}\n`)
  process.stdout.write(`CITATION-CHECK-RESULT ${citSummary}\n`)
  process.exit(1)
}
process.stdout.write(`DOCSLINK-CHECK-OK ${summary}\n`)
process.stdout.write(`CITATION-CHECK-OK ${citSummary}\n`)
process.exit(0)
