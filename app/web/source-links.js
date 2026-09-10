'use strict';
/**
 * "View on GitHub" links for the code samples on each lab bench.
 *
 * The snippets in app/web/labs/*.js are hand-condensed versions of the real
 * handlers, so we can't diff them against the source to find their line
 * numbers. Instead we ANCHOR each snippet to a distinctive line of the real
 * file (by default the route registration the action calls) and walk forward
 * over balanced brackets to find where that block ends. That yields a
 * #L<start>-L<end> range that survives edits above and below it — no line
 * numbers are written down anywhere.
 *
 * Most actions need no configuration: the anchor is derived from the action's
 * method + path. An action can override it with:
 *
 *   code: {
 *     src: {
 *       file: 'app/routes/a02-...js',        // optional, defaults to the lab's route file
 *       vuln: { anchor: 'vuln.use((err,', to: 'someLaterLine' },
 *       safe: { file: 'app/lib/ssrf-guard.js', anchor: 'function assertPublicUrl' },
 *     },
 *   }
 *
 * `anchor` is a substring of the first line of the block; `to` is an optional
 * substring of a later line whose own block-end becomes the range end.
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const ROUTES_DIR = path.join(ROOT, 'app', 'routes');
const REF = process.env.REPO_REF || 'main';

// Lines are cached per file and invalidated by mtime, so editing a route
// during a workshop updates the links on the next page load.
const fileCache = new Map();

function readLines(relPath) {
  const abs = path.join(ROOT, relPath);
  let mtime;
  try { mtime = fs.statSync(abs).mtimeMs; } catch { return null; }
  const hit = fileCache.get(relPath);
  if (hit && hit.mtime === mtime) return hit.lines;
  let lines;
  try { lines = fs.readFileSync(abs, 'utf8').split('\n'); } catch { return null; }
  fileCache.set(relPath, { mtime, lines });
  return lines;
}

// The route module for a lab: app/routes/<code>-<whatever>.js.
const routeFileCache = new Map();
function routeFileFor(code) {
  if (routeFileCache.has(code)) return routeFileCache.get(code);
  let found = null;
  try {
    const name = fs.readdirSync(ROUTES_DIR).find((f) => f.startsWith(`${code}-`) && f.endsWith('.js'));
    if (name) found = `app/routes/${name}`;
  } catch { /* no routes dir — links are simply omitted */ }
  routeFileCache.set(code, found);
  return found;
}

/**
 * Walk from `start` until every bracket opened on the way is closed again,
 * skipping strings, template literals and comments. Returns the 0-based index
 * of the last line of the block (== start for a single-line statement).
 */
function blockEnd(lines, start, limit = 200) {
  let depth = 0;
  let opened = false;
  let inBlockComment = false;
  for (let i = start; i < lines.length && i - start < limit; i += 1) {
    const line = lines[i];
    let quote = null;               // ' " or ` while inside a string
    for (let j = 0; j < line.length; j += 1) {
      const c = line[j];
      if (inBlockComment) {
        if (c === '*' && line[j + 1] === '/') { inBlockComment = false; j += 1; }
        continue;
      }
      if (quote) {
        if (c === '\\') { j += 1; continue; }
        if (c === quote) quote = null;
        continue;
      }
      if (c === '/' && line[j + 1] === '/') break;                    // line comment
      if (c === '/' && line[j + 1] === '*') { inBlockComment = true; j += 1; continue; }
      if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
      if (c === '(' || c === '[' || c === '{') { depth += 1; opened = true; continue; }
      if (c === ')' || c === ']' || c === '}') depth -= 1;
    }
    if (opened && depth <= 0) return i;
  }
  return start;
}

function findLine(lines, needle, from = 0) {
  for (let i = from; i < lines.length; i += 1) if (lines[i].includes(needle)) return i;
  return -1;
}

// Candidate anchors for an action, most specific first. Express paths use
// `:id` where the bench spec uses `{id}`, and shared handlers are registered
// inside a helper as `router.get(...)`, so both prefixes are tried. Paths that
// point at a statically served file (/files/.env.backup) fall back to their
// parent mounts (/files).
function autoAnchors(action, side) {
  const method = String(action.method || 'GET').toLowerCase();
  const full = String(action.path || '/').replace(/\{(\w+)\}/g, ':$1');
  const paths = [full];
  if (full.endsWith('/') && full.length > 1) paths.push(full.slice(0, -1));
  for (let p = full; p.lastIndexOf('/') > 0; ) {
    p = p.slice(0, p.lastIndexOf('/'));
    paths.push(p);
  }
  const verbs = [method, 'all', 'use'];
  const anchors = [];
  for (const p of paths) {
    for (const verb of verbs) {
      anchors.push(`${side}.${verb}('${p}'`);
      anchors.push(`router.${verb}('${p}'`);
    }
  }
  return anchors;
}

function locate(spec, code, action, side) {
  const file = (spec && spec.file) || routeFileFor(code);
  if (!file) return null;
  const lines = readLines(file);
  if (!lines) return null;

  let start = -1;
  if (spec && spec.anchor) {
    start = findLine(lines, spec.anchor);
  } else {
    for (const anchor of autoAnchors(action, side)) {
      start = findLine(lines, anchor);
      if (start >= 0) break;
    }
  }
  if (start < 0) return null;

  let end = blockEnd(lines, start);
  if (spec && spec.to) {
    const toLine = findLine(lines, spec.to, start);
    if (toLine >= 0) end = Math.max(end, blockEnd(lines, toLine));
  }
  return { file, start: start + 1, end: end + 1 };
}

function link(repo, hit, defaultFile) {
  const range = hit.end > hit.start ? `L${hit.start}-L${hit.end}` : `L${hit.start}`;
  // Most snippets live in the lab's own route file, so naming it in every
  // header would just be noise — only call the file out when it's a different
  // one (a shared helper, say).
  const name = hit.file.slice(hit.file.lastIndexOf('/') + 1);
  const label = hit.file === defaultFile ? `GitHub · ${range}` : `${name} ${range}`;
  return {
    url: `${repo}/blob/${REF}/${hit.file}#${range}`,
    label,
    title: `${hit.file} lines ${hit.start}\u2013${hit.end}`,
  };
}

/**
 * Return a copy of `bench` whose code samples carry `vulnLink` / `safeLink`
 * ({url, label, title}) pointing at the real source on GitHub. Sides with no
 * snippet, or whose anchor can't be found, are simply left without a link.
 */
function withSourceLinks(code, bench, repo) {
  if (!bench || !Array.isArray(bench.actions)) return bench;
  const actions = bench.actions.map((action) => {
    if (!action.code) return action;
    const src = action.code.src || {};
    const next = Object.assign({}, action.code);
    delete next.src;
    for (const side of ['vuln', 'safe']) {
      // `side: false` means "there is deliberately no such code" (A09's
      // missing /alerts route), so it stays unlinked.
      if (action.code[side] == null || src[side] === false) continue;
      const spec = Object.assign({}, src.file ? { file: src.file } : null, src[side]);
      const hit = locate(spec, code, action, side);
      if (hit) next[`${side}Link`] = link(repo, hit, routeFileFor(code));
    }
    return Object.assign({}, action, { code: next });
  });
  return Object.assign({}, bench, { actions });
}

module.exports = { withSourceLinks };
