/* Shared interactive "lab bench" renderer.
 * Reads a declarative spec from <script type="application/json" id="lab-data">
 * and builds the try-it UI. No inline scripts, so a strict CSP is fine. Each
 * action can run against /vuln/<code> or /safe/<code>; results render as JSON,
 * raw text, or a live iframe (so stored/reflected XSS actually executes). */
(function () {
  var data = JSON.parse(document.getElementById('lab-data').textContent);
  var CODE = data.code;
  var root = document.getElementById('bench');
  var side = 'vuln';

  function subst(str, vals) {
    return String(str).replace(/\{(\w+)\}/g, function (_, k) {
      return vals[k] == null ? '' : vals[k];
    });
  }
  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }

  // vuln/safe toggle
  var toggle = el('div', 'toggle');
  ['vuln', 'safe'].forEach(function (s) {
    var b = el('button', s === side ? 'on' : '', s === 'vuln' ? '🔓 Vulnerable' : '🔒 Fixed');
    b.dataset.side = s;
    b.onclick = function () {
      side = s;
      Array.prototype.forEach.call(toggle.children, function (c) {
        c.className = c.dataset.side === side ? 'on' : '';
      });
    };
    toggle.appendChild(b);
  });
  root.appendChild(toggle);

  (data.bench.actions || []).forEach(function (a) {
    var card = el('div', 'action');
    card.appendChild(el('h4', null, a.title));
    if (a.description) card.appendChild(el('div', 'desc', a.description));

    var fields = el('div', 'fields');
    var inputs = {};
    (a.inputs || []).forEach(function (inp) {
      var f = el('div', 'field');
      f.appendChild(el('label', null, inp.label || inp.name));
      var ctl;
      if (inp.options) {
        ctl = el('select');
        inp.options.forEach(function (o) {
          var op = el('option', null, o); op.value = o; ctl.appendChild(op);
        });
      } else {
        ctl = el('input');
        ctl.type = 'text';
        if (inp.placeholder) ctl.placeholder = inp.placeholder;
        if (inp.size) ctl.style.minWidth = inp.size + 'px';
      }
      ctl.value = inp.default != null ? inp.default : '';
      inputs[inp.name] = ctl;
      f.appendChild(ctl);
      fields.appendChild(f);
    });
    if ((a.inputs || []).length) card.appendChild(fields);

    // PRIMARY, always visible: the exact commands to run by hand. They update
    // live as you edit the inputs, and each has a Copy button.
    var term = el('div', 'terminal');
    term.appendChild(el('div', 'termhead', '⌨️  Try it yourself — copy into your terminal'));
    var curlBody = el('div', 'curlbody');
    term.appendChild(curlBody);
    card.appendChild(term);
    Object.keys(inputs).forEach(function (k) {
      inputs[k].addEventListener('input', function () { renderCurl(a, inputs, curlBody); });
      inputs[k].addEventListener('change', function () { renderCurl(a, inputs, curlBody); });
    });
    renderCurl(a, inputs, curlBody);
    if (a.hint) card.appendChild(el('div', 'termhint', '💡 ' + a.hint));

    // SECONDARY, tucked away: the same requests as one-click buttons.
    var out = el('div', 'out');
    var det = el('details', 'clicky');
    det.appendChild(el('summary', null, '🖱️ Prefer clicking? Run it in the browser instead'));
    var runRow = el('div', 'run');
    (a.sides || ['vuln', 'safe']).forEach(function (s) {
      var btn = el('button', 'go ' + s, s === 'vuln' ? 'Run on /vuln' : 'Run on /safe');
      btn.onclick = function () { run(a, s, inputs, out); };
      runRow.appendChild(btn);
    });
    det.appendChild(runRow);
    det.appendChild(out);
    card.appendChild(det);

    if (a.expect) {
      var ex = el('div', 'expect');
      if (a.expect.vuln) { var bv = el('b', 'v', 'vuln: '); ex.appendChild(bv); ex.appendChild(document.createTextNode(a.expect.vuln + '  ')); }
      if (a.expect.safe) { var bs = el('b', 's', 'safe: '); ex.appendChild(bs); ex.appendChild(document.createTextNode(a.expect.safe)); }
      card.appendChild(ex);
    }
    root.appendChild(card);
  });

  function buildUrl(a, s, vals) {
    var p = subst(a.path || '/', vals);
    var url = '/' + s + '/' + CODE + p;
    var qs = [];
    if (a.query) Object.keys(a.query).forEach(function (k) {
      qs.push(encodeURIComponent(k) + '=' + encodeURIComponent(subst(a.query[k], vals)));
    });
    // GET inputs not used in path/query/headers default to query params
    if ((a.method || 'GET') === 'GET' && a.autoQuery !== false) {
      (a.inputs || []).forEach(function (inp) {
        if (inp.in === 'query') qs.push(encodeURIComponent(inp.name) + '=' + encodeURIComponent(vals[inp.name]));
      });
    }
    if (qs.length) url += (url.indexOf('?') >= 0 ? '&' : '?') + qs.join('&');
    return url;
  }

  // Build the exact request an action makes — used by BOTH the Run buttons and
  // the "curl" accordion, so the copy-paste command can never drift from what
  // the button actually sends. Returns {url, method, headers, body, err}.
  function buildRequest(a, s, vals) {
    var url = buildUrl(a, s, vals);
    var method = a.method || 'GET';
    var headers = {};
    if (a.headers) Object.keys(a.headers).forEach(function (h) { headers[h] = subst(a.headers[h], vals); });
    var body = null;
    if (method !== 'GET') {
      if (a.rawBody) {
        headers['content-type'] = 'application/json';
        try { body = JSON.stringify(JSON.parse(subst(a.rawBody, vals))); }
        catch (e) { return { url: url, method: method, headers: headers, body: null, err: 'bad JSON in body: ' + e.message }; }
      } else {
        var b = {};
        if (a.body) Object.keys(a.body).forEach(function (k) { b[k] = subst(a.body[k], vals); });
        (a.inputs || []).forEach(function (inp) {
          if (inp.in !== 'body') return;
          if (inp.json) { try { b[inp.name] = JSON.parse(vals[inp.name]); } catch (e) { b[inp.name] = vals[inp.name]; } }
          else b[inp.name] = vals[inp.name];
        });
        if ((a.bodyType || 'json') === 'form') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          body = new URLSearchParams(b).toString();
        } else {
          headers['content-type'] = 'application/json';
          body = JSON.stringify(b);
        }
      }
    }
    return { url: url, method: method, headers: headers, body: body, err: null };
  }

  // Wrap a value as a single-quoted shell argument, safely — payloads can
  // contain ' (SQLi, XSS), and encodeURIComponent leaves ' literal in URLs.
  function sq(v) { return "'" + String(v).replace(/'/g, "'\\''") + "'"; }

  // Format a request as a copy-pasteable, shell-safe curl one-liner.
  function buildCurl(a, s, vals) {
    var req = buildRequest(a, s, vals);
    var parts = ['curl -s'];
    if (req.method !== 'GET') parts.push('-X ' + req.method);
    Object.keys(req.headers).forEach(function (h) {
      parts.push('-H ' + sq(h + ': ' + req.headers[h]));
    });
    if (req.body != null) parts.push('-d ' + sq(req.body));
    parts.push(sq(location.origin + req.url));
    return parts.join(' ');
  }

  function readVals(inputEls) {
    var vals = {};
    Object.keys(inputEls).forEach(function (k) { vals[k] = inputEls[k].value; });
    return vals;
  }

  function flash(btn) { btn.textContent = 'Copied!'; setTimeout(function () { btn.textContent = 'Copy'; }, 1200); }
  function copyText(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { flash(btn); }, function () { legacyCopy(text, btn); });
    } else { legacyCopy(text, btn); }
  }
  function legacyCopy(text, btn) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta); flash(btn);
    } catch (e) { /* no-op */ }
  }

  // Render one curl block per side (recomputed from current inputs each time the
  // accordion opens, so the command always matches what the buttons would send).
  function renderCurl(a, inputEls, container) {
    container.innerHTML = '';
    var vals = readVals(inputEls);
    (a.sides || ['vuln', 'safe']).forEach(function (s) {
      var block = el('div', 'curlblock');
      block.appendChild(el('div', 'curlhead ' + s, s === 'vuln' ? '/vuln — broken' : '/safe — fixed'));
      var wrap = el('div', 'codewrap');
      var cmd = buildCurl(a, s, vals);
      wrap.appendChild(el('code', null, cmd));
      var copy = el('button', 'copy', 'Copy');
      copy.onclick = function () { copyText(cmd, copy); };
      wrap.appendChild(copy);
      block.appendChild(wrap);
      container.appendChild(block);
    });
    if (a.render === 'iframe') {
      container.appendChild(el('div', 'curlnote', 'This action renders HTML — in a terminal the curl shows the raw response; in the page it runs live in a frame.'));
    }
  }

  function run(a, s, inputEls, out) {
    var vals = readVals(inputEls);
    var url = buildUrl(a, s, vals);
    var method = a.method || 'GET';
    out.className = 'out show';
    out.innerHTML = '';
    out.appendChild(metaBar(s, method + ' ' + url));

    if (a.render === 'iframe') {
      var note = el('div', 'framenote', 'Live render of ' + url + ' — on /vuln any injected script executes here.');
      out.appendChild(note);
      var f = el('iframe'); f.src = url; out.appendChild(f);
      return;
    }

    var req = buildRequest(a, s, vals);
    if (req.err) { out.appendChild(el('pre', null, req.err)); return; }
    var opts = { method: req.method, headers: req.headers };
    if (req.body != null) opts.body = req.body;

    var pre = el('pre', null, '… running');
    out.appendChild(pre);
    fetch(url, opts).then(function (r) {
      var ct = r.headers.get('content-type') || '';
      return r.text().then(function (t) {
        var shown = t;
        if (ct.indexOf('application/json') >= 0) { try { shown = JSON.stringify(JSON.parse(t), null, 2); } catch (e) {} }
        pre.textContent = 'HTTP ' + r.status + '\n\n' + shown;
      });
    }).catch(function (e) { pre.textContent = 'request failed: ' + e.message; });
  }

  function metaBar(s, label) {
    var m = el('div', 'meta ' + s, (s === 'vuln' ? '🔓 VULN  ' : '🔒 SAFE  ') + label);
    return m;
  }

  // ===========================================================================
  // Web console — paste a curl command, it runs against THIS lab via fetch.
  // It is a curl interpreter, not a shell: only http(s) to this origin, no
  // arbitrary commands. Cross-origin targets are blocked by the page CSP, which
  // is the point — the SSRF target is only reachable through the app.
  // ===========================================================================
  function tokenizeShell(s) {
    s = s.replace(/\\\r?\n/g, ' ');            // join line continuations
    var tokens = [], cur = '', q = null, pushed = false;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) {
        if (c === q) { q = null; pushed = true; }
        else if (q === '"' && c === '\\' && i + 1 < s.length) { cur += s[++i]; }
        else cur += c;
      } else if (c === "'" || c === '"') { q = c; pushed = true; }
      else if (c === '\\' && i + 1 < s.length) { cur += s[++i]; }
      else if (/\s/.test(c)) { if (cur !== '' || pushed) { tokens.push(cur); cur = ''; pushed = false; } }
      else cur += c;
    }
    if (cur !== '' || pushed) tokens.push(cur);
    return tokens;
  }

  var NOARG = { '-s': 1, '-S': 1, '-k': 1, '-i': 1, '-I': 1, '-v': 1, '-L': 1, '--silent': 1, '--insecure': 1, '--location': 1, '--compressed': 1, '--fail': 1, '-f': 1, '-sS': 1, '-sk': 1, '-ks': 1 };

  function parseCurl(cmd) {
    var t = tokenizeShell(cmd.trim());
    if (!t.length || t[0] !== 'curl') throw new Error("command must start with 'curl'");
    var p = { method: null, headers: {}, data: [], enc: [], url: null, get: false };
    for (var i = 1; i < t.length; i++) {
      var a = t[i];
      if (a === '-X' || a === '--request') p.method = t[++i];
      else if (a === '-H' || a === '--header') { var h = t[++i] || ''; var idx = h.indexOf(':'); if (idx > 0) p.headers[h.slice(0, idx).trim().toLowerCase()] = h.slice(idx + 1).trim(); }
      else if (a === '-d' || a === '--data' || a === '--data-raw' || a === '--data-binary' || a === '--data-ascii') p.data.push(t[++i]);
      else if (a === '--data-urlencode') p.enc.push(t[++i]);
      else if (a === '-G' || a === '--get') p.get = true;
      else if (a === '-b' || a === '--cookie') p.headers['cookie'] = t[++i];
      else if (a === '-A' || a === '--user-agent') p.headers['user-agent'] = t[++i];
      else if (a === '-e' || a === '--referer') p.headers['referer'] = t[++i];
      else if (a === '-o' || a === '--output' || a === '-w' || a === '--write-out' || a === '--max-time' || a === '--connect-timeout') { i++; /* skip arg */ }
      else if (NOARG[a]) { /* flag with no argument */ }
      else if (a.charAt(0) === '-') { /* unknown flag: ignore, assume no arg */ }
      else p.url = a;
    }
    if (!p.url) throw new Error('no URL found');
    return p;
  }

  function encPair(kv) {
    var eq = kv.indexOf('=');
    return eq >= 0 ? encodeURIComponent(kv.slice(0, eq)) + '=' + encodeURIComponent(kv.slice(eq + 1)) : encodeURIComponent(kv);
  }

  // Turn a parsed curl into {url, opts} for fetch.
  function curlToFetch(p) {
    var headers = {}; Object.keys(p.headers).forEach(function (k) { headers[k] = p.headers[k]; });
    var url = p.url, body = null;
    var parts = p.data.slice().concat(p.enc.map(encPair));
    var hasData = parts.length > 0;
    var method = p.method || (hasData && !p.get ? 'POST' : 'GET');
    if (p.get && hasData) {
      url += (url.indexOf('?') >= 0 ? '&' : '?') + parts.join('&');
    } else if (hasData) {
      if (p.data.length === 1 && p.enc.length === 0 && /^[\[{]/.test(p.data[0].trim())) {
        body = p.data[0];
        if (!headers['content-type']) headers['content-type'] = 'application/json';
      } else {
        body = parts.join('&');
        if (!headers['content-type']) headers['content-type'] = 'application/x-www-form-urlencoded';
      }
    }
    return { url: url, opts: { method: method, headers: headers, body: body, redirect: 'manual' } };
  }

  function initConsole() {
    var host = document.getElementById('webconsole');
    if (!host) return;
    var head = el('div', 'wc-head');
    head.appendChild(el('span', null, '🖥️  Web console'));
    head.appendChild(el('span', 'wc-hint', 'runs curl via fetch — not a shell'));
    var out = el('div', 'wc-out');
    out.appendChild(el('div', 'wc-seed', 'Paste a curl from any action above, then Run (⌘/Ctrl+Enter). Requests go to this lab; cross-origin targets are blocked by design.'));
    var inWrap = el('div', 'wc-in');
    var ta = el('textarea');
    ta.setAttribute('spellcheck', 'false'); ta.setAttribute('autocomplete', 'off');
    ta.placeholder = "curl -s 'https://localhost:3000/vuln/a01/invoices/1004?as=alice'";
    var actions = el('div', 'wc-actions');
    var run = el('button', 'wc-run', 'Run ▸');
    var clear = el('button', 'wc-clear', 'Clear');
    actions.appendChild(run); actions.appendChild(clear);
    actions.appendChild(el('span', 'wc-hint', '⌘/Ctrl+Enter'));
    inWrap.appendChild(ta); inWrap.appendChild(actions);
    host.appendChild(head); host.appendChild(out); host.appendChild(inWrap);

    function scroll() { out.scrollTop = out.scrollHeight; }
    function runCmd() {
      var cmd = ta.value.trim();
      if (!cmd) return;
      var seed = out.querySelector('.wc-seed'); if (seed) seed.remove();
      out.appendChild(el('div', 'wc-cmd', '$ ' + cmd.replace(/\\\r?\n\s*/g, ' ').replace(/\s+/g, ' ')));
      var line = el('div', 'wc-res', '… running');
      out.appendChild(line); scroll();
      var req;
      try { req = curlToFetch(parseCurl(cmd)); }
      catch (e) { line.className = 'wc-res wc-err'; line.textContent = 'parse error: ' + e.message; return; }
      fetch(req.url, req.opts).then(function (r) {
        var ct = r.headers.get('content-type') || '';
        return r.text().then(function (txt) {
          var shown = txt;
          if (ct.indexOf('application/json') >= 0) { try { shown = JSON.stringify(JSON.parse(txt), null, 2); } catch (e) {} }
          line.innerHTML = '';
          line.appendChild(el('span', 'wc-status', 'HTTP ' + r.status));
          line.appendChild(document.createTextNode('\n' + shown));
          scroll();
        });
      }).catch(function (e) {
        line.className = 'wc-res wc-err';
        line.textContent = 'request failed: ' + e.message + '\n(cross-origin targets are blocked — reach internal services through the app, e.g. the SSRF action)';
        scroll();
      });
    }
    run.onclick = runCmd;
    clear.onclick = function () { out.innerHTML = ''; };
    ta.addEventListener('keydown', function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); runCmd(); }
    });
  }

  initConsole();
})();
