'use strict';
// Server-side rendering for the LinkedIn-style front end: a feed of lab "posts"
// and one interactive profile page per lab. Content comes from app/web/labs/*,
// and the "Read the lab" tab renders labs/<code>/README.md inline.
const fs = require('node:fs');
const path = require('node:path');
const { renderMarkdown } = require('./markdown');

const REPO = 'https://github.com/afbase/devcolor';
const LABS_DIR = path.join(__dirname, '..', '..', 'labs');
// Where the monitoring stack lives. Localhost by default; set these when the
// lab is published behind a tunnel so the links work for everyone, not just
// whoever is sitting at the host.
const GRAFANA_URL = process.env.GRAFANA_URL || 'http://localhost:3001';
const PROMETHEUS_URL = process.env.PROMETHEUS_URL || 'http://localhost:9090';

function esc(s) {
  return String(s == null ? '' : s)
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
// Escape post text, then lightly style #hashtags and @mentions.
function richText(s) {
  return esc(s).replace(/(^|\s)([#@][\w-]+)/g, '$1<span class="tag">$2</span>');
}

// Stamp /static URLs with the file's mtime, so an edited stylesheet or script
// can never be served from a stale browser cache during a workshop.
function asset(file) {
  let v = '1';
  try { v = String(Math.floor(fs.statSync(path.join(__dirname, '..', 'public', file)).mtimeMs)); }
  catch { /* fall through to the constant */ }
  return `/static/${file}?v=${v}`;
}

function shell({ title, body, csp }) {
  const head = csp ? `<meta http-equiv="Content-Security-Policy" content="${csp}">` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>${head}
<link rel="stylesheet" href="${asset('linkedin.css')}"></head><body>
${body}
<div class="footer">Deliberately vulnerable — for learning only. Reference:
  <a href="https://owasp.org/Top10/2025/" target="_blank" rel="noreferrer">owasp.org/Top10/2025</a></div>
</body></html>`;
}

function meCard() {
  return `<div class="card pcard">
    <div class="cover"></div>
    <div class="body">
      <div class="avatar" style="background:#111827">YOU</div>
      <h2>You, the Pentester</h2>
      <div class="sub">Learning the OWASP Top 10 by breaking things</div>
      <div class="stat"><span>Labs to try</span><b>10</b></div>
      <div class="stat"><span>Profiles saved</span><b>500+</b></div>
    </div>
    <div style="padding:6px 8px 10px" class="railnav">
      <a href="/">🏠 Home feed</a>
      <a href="${esc(GRAFANA_URL)}" target="_blank">📊 Grafana</a>
      <a href="${esc(PROMETHEUS_URL)}" target="_blank">🔥 Prometheus</a>
      <a href="/metrics">📈 /metrics</a>
    </div>
  </div>`;
}

function rightRail() {
  return `<div class="col aside">
    <div class="card pad">
      <div class="banner"><b>⚠ Deliberately vulnerable.</b> Every profile below is a live target. Localhost only — never deploy this.</div>
    </div>
    <div class="card pad">
      <h3>OWASP in the news</h3>
      <ul class="news" style="padding:0;margin:0">
        <li><span class="dot">•</span> <b>Supply-chain attacks keep climbing</b><span class="mini">A03 · voted #1 in the community survey</span></li>
        <li><span class="dot">•</span> <b>Misconfiguration is the big mover</b><span class="mini">A02 · #5 → #2 for 2025</span></li>
        <li><span class="dot">•</span> <b>New: mishandled error conditions</b><span class="mini">A10 · brand-new category</span></li>
      </ul>
    </div>
    <div class="card pad">
      <h3>Prove your work</h3>
      <div class="mini">Every fix is backed by a test.</div>
      <div class="ops"><a href="https://owasp.org/Top10/2025/" target="_blank">↗ Read the official Top 10</a></div>
    </div>
  </div>`;
}

function postCard(lab) {
  const p = lab.persona, po = lab.post;
  return `<div class="card post">
    <div class="head">
      <a href="/lab/${lab.code}"><div class="avatar" style="background:${esc(p.color)}">${lab.code.toUpperCase()}</div></a>
      <div class="who">
        <a class="name" href="/lab/${lab.code}">${esc(lab.title)}</a>
        <div class="t">${esc(lab.rank || '')}</div>
        <div class="t">${esc(po.time || '2h')} · 🌐 Public</div>
      </div>
      <div class="rank">${lab.code.toUpperCase()}</div>
    </div>
    <div class="text">${richText(po.summary)}</div>
    <div class="figure"><a href="/lab/${lab.code}">
      <div class="k">OWASP ${lab.code.toUpperCase()} · ${esc(lab.title)}</div>
      <div class="h">${esc(po.headline || 'Visit the lab to try it')}</div>
      <div class="d">${esc(po.cta || 'Run the vulnerability yourself')}</div>
      <span class="go">Open lab &amp; try it →</span>
    </a></div>
    <div class="social"><span class="reacts">${esc(po.reactions || 0)}</span>
      <span>${esc(po.comments || 0)} comments · ${esc(po.reposts || 0)} reposts</span></div>
    <div class="bar">
      <button>👍 Like</button><button>💬 Comment</button>
      <button>🔁 Repost</button><button><a href="/lab/${lab.code}" style="color:inherit">➤ Try it</a></button>
    </div>
  </div>`;
}

function renderFeed(labs) {
  const body = `<div class="shell">
    <div class="col">${meCard()}</div>
    <div class="col">
      <div class="card pad composer" style="display:flex;gap:10px;align-items:center">
        <div class="avatar" style="width:44px;height:44px;background:#111827;font-size:15px">YOU</div>
        <div style="flex:1;border:1px solid var(--line);border-radius:999px;padding:10px 16px;color:var(--muted)">
          Start a post… or scroll down and start breaking one 👇</div>
      </div>
      ${labs.map(postCard).join('\n')}
    </div>
    ${rightRail()}
  </div>`;
  return shell({ title: 'OWASP Top 10:2025 — Feed', body });
}

// The lab write-up, rendered from disk on each request so edits to the README
// show up on reload. Relative links in the doc are rewritten to point at the
// repo, since they mean nothing from /lab/<code>.
function labGuide(code) {
  const file = path.join(LABS_DIR, code, 'README.md');
  let md;
  try {
    md = fs.readFileSync(file, 'utf8');
  } catch {
    return `<p class="mini">No write-up on disk yet for ${esc(code)} \u2014 expected
      <code>labs/${esc(code)}/README.md</code>.</p>`;
  }
  return renderMarkdown(md, { docDir: `labs/${code}`, repo: REPO });
}

function renderProfile(lab) {
  const p = lab.persona, pr = lab.profile;
  const chips = (pr.highlights || []).map((h) => `<span class="chip">${esc(h)}</span>`).join(' ');
  const labData = JSON.stringify({ code: lab.code, bench: lab.bench })
    .replace(/</g, '\\u003c'); // safe to embed in a JSON script block
  const body = `<div class="shell" style="grid-template-columns:minmax(0,1fr) 380px;max-width:1320px">
    <div class="col">
      <div class="card profile">
        <div class="cover" style="background:${esc(p.banner || 'linear-gradient(120deg,#0a66c2,#378fe9)')}"></div>
        <div class="idrow">
          <div class="avatar" style="background:${esc(p.color)}">${lab.code.toUpperCase()}</div>
          <h1>${esc(lab.title)}</h1>
          <div class="headline">OWASP ${lab.code.toUpperCase()} · ${esc(lab.rank || '')}</div>
          <div class="actions">
            <a class="btn ghost" href="/">← Back to feed</a>
          </div>
        </div>
      </div>
      <div class="card section bgcard">
        <ul class="nav nav-tabs" role="tablist">
          <li class="nav-item"><a class="nav-link active" href="#panel-bg" role="tab"
            aria-selected="true" data-tab="bg">Background</a></li>
          <li class="nav-item"><a class="nav-link" href="#panel-guide" role="tab"
            aria-selected="false" data-tab="guide">Read the lab</a></li>
        </ul>
        <div class="tab-content">
          <div class="tab-pane active" id="panel-bg" data-panel="bg" role="tabpanel">
            <div class="about">${esc(pr.about || '')}</div>
            ${chips ? `<div class="chips">${chips}</div>` : ''}
          </div>
          <div class="tab-pane" id="panel-guide" data-panel="guide" role="tabpanel">
            <div class="doc-head">
              <span class="doc-path">labs/${lab.code}/README.md</span>
              <a class="btn ghost" href="${REPO}/blob/main/labs/${lab.code}/README.md"
                target="_blank" rel="noreferrer">↗ View on GitHub</a>
            </div>
            <div class="doc-scroll" tabindex="0">
              <div class="lab-doc">${labGuide(lab.code)}</div>
            </div>
          </div>
        </div>
      </div>
      <div class="card pad section bench">
        <h3>🧪 Live vulnerability bench — <span style="color:var(--red)">${lab.code.toUpperCase()}</span></h3>
        <p class="mini">${esc(lab.bench.intro || 'Each action has its own /vuln and /safe buttons — run both and compare.')}</p>
        <div id="bench"></div>
      </div>
    </div>
    <div class="col aside sticky-rail">
      <div class="webconsole" id="webconsole"></div>
      <div class="card pad">
        <div class="banner"><b>⚠ Live target.</b> The actions below hit the real vulnerable and fixed endpoints.</div>
      </div>
      <div class="card pad">
        <h3>${lab.code.toUpperCase()} · ${esc(lab.title)}</h3>
        <div class="mini">${esc(lab.rank || '')}</div>
        <div class="ops">
          <a href="/vuln/${lab.code}/" target="_blank">↗ /vuln/${lab.code}</a>
          <a href="/safe/${lab.code}/" target="_blank">↗ /safe/${lab.code}</a>
        </div>
      </div>
    </div>
  </div>
  <script type="application/json" id="lab-data">${labData}</script>
  <script src="${asset('bench.js')}"></script>`;
  // Our own chrome is locked down; the vuln endpoints (shown in iframes) are not.
  return shell({ title: `OWASP ${lab.code.toUpperCase()} · ${lab.title}`, body,
    csp: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-src 'self'" });
}

module.exports = { renderFeed, renderProfile, esc };
