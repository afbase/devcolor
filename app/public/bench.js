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

    var out = el('div', 'out');
    var runRow = el('div', 'run');
    var sides = a.sides || ['vuln', 'safe'];
    sides.forEach(function (s) {
      var btn = el('button', 'go ' + s, s === 'vuln' ? 'Run on /vuln' : 'Run on /safe');
      btn.onclick = function () { run(a, s, inputs, out); };
      runRow.appendChild(btn);
    });
    if (a.hint) runRow.appendChild(el('span', 'hint', a.hint));
    card.appendChild(runRow);
    card.appendChild(out);

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

  function run(a, s, inputEls, out) {
    var vals = {};
    Object.keys(inputEls).forEach(function (k) { vals[k] = inputEls[k].value; });
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

    var opts = { method: method, headers: {} };
    if (a.headers) Object.keys(a.headers).forEach(function (h) { opts.headers[h] = subst(a.headers[h], vals); });
    if (method !== 'GET') {
      var body = {};
      if (a.body) Object.keys(a.body).forEach(function (k) { body[k] = subst(a.body[k], vals); });
      (a.inputs || []).forEach(function (inp) { if (inp.in === 'body') body[inp.name] = vals[inp.name]; });
      if ((a.bodyType || 'json') === 'form') {
        opts.headers['content-type'] = 'application/x-www-form-urlencoded';
        opts.body = new URLSearchParams(body).toString();
      } else {
        opts.headers['content-type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
    }

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
