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
})();
