package main

import (
	"encoding/json"
	"html"
	"os"
	"strconv"
	"strings"
)

func (r *report) writeHTML(path string) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	js := strings.ReplaceAll(string(data), "</", "<\\/")

	out := strings.Replace(htmlTemplate, "__TITLE__", html.EscapeString(strings.Join(r.Command, " ")), 1)
	out = strings.Replace(out, "__DATA__", js, 1)

	os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 == nil && err2 == nil {
		os.Chown(path, uid, gid)
	}
	return nil
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sus report</title>
<style>
:root {
  --bg: #fafaf8; --panel: #ffffff; --ink: #1d1f23; --muted: #6b7078; --line: #e3e3de;
  --red: #b3261e; --green: #1b7a3d; --yellow: #8a6100; --cyan: #0b6a82; --accent: #2f5fd0;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #15171a; --panel: #1d2024; --ink: #e6e7e9; --muted: #9096a0; --line: #2d3137;
    --red: #ff7b72; --green: #56d364; --yellow: #e3b341; --cyan: #56c1d6; --accent: #79a2ff;
  }
}
:root[data-theme="dark"] {
  --bg: #15171a; --panel: #1d2024; --ink: #e6e7e9; --muted: #9096a0; --line: #2d3137;
  --red: #ff7b72; --green: #56d364; --yellow: #e3b341; --cyan: #56c1d6; --accent: #79a2ff;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 var(--sans); }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font: 600 20px var(--sans); margin: 0 0 4px; word-break: break-word; }
.meta { color: var(--muted); font-size: 13px; }
.meta b { color: var(--ink); font-weight: 600; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; margin: 16px 0; }
.card h2 { font: 600 13px var(--sans); text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 0 0 8px; }
.findings ul { padding: 0; margin: 0 0 8px; }
.findings li { font-family: var(--mono); font-size: 13px; margin: 2px 0; list-style: none; word-break: break-all; }
.findings h3 { font: 600 13px var(--sans); margin: 10px 0 2px; }
.sev-high { color: var(--red); } .sev-medium { color: var(--yellow); } .sev-low { color: var(--muted); } .sev-none { color: var(--green); }
.badge { display: inline-block; font: 700 12px var(--sans); letter-spacing: .05em; text-transform: uppercase; padding: 2px 8px; border: 1px solid currentColor; border-radius: 4px; margin-right: 8px; }
.notes { color: var(--yellow); font-size: 13px; margin-top: 6px; }
.none { color: var(--muted); }
.ioc-group { margin: 8px 0; }
.ioc-group h3 { font: 600 13px var(--sans); margin: 0 0 2px; display: flex; gap: 8px; align-items: center; }
.ioc-group pre { margin: 0; font: 13px var(--mono); white-space: pre-wrap; word-break: break-all; }
.copy { font: 12px var(--sans); border: 1px solid var(--line); background: var(--panel); color: var(--ink); border-radius: 4px; padding: 1px 8px; cursor: pointer; }
.anom { color: var(--red); font-weight: 400; }
.bar { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; position: sticky; top: 0; background: var(--bg); padding: 10px 0; z-index: 2; border-bottom: 1px solid var(--line); }
.bar input[type=search] { flex: 1 1 220px; min-width: 160px; padding: 6px 10px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); color: var(--ink); font: 13px var(--mono); }
.bar label { font-size: 13px; color: var(--muted); display: inline-flex; gap: 4px; align-items: center; cursor: pointer; }
.tabs button { font: 13px var(--sans); border: 1px solid var(--line); background: var(--panel); color: var(--ink); padding: 5px 12px; cursor: pointer; }
.tabs button:first-child { border-radius: 6px 0 0 6px; } .tabs button:last-child { border-radius: 0 6px 6px 0; border-left: 0; }
.tabs button[aria-pressed=true] { background: var(--accent); color: #fff; border-color: var(--accent); }
details { margin: 4px 0 4px 14px; border-left: 1px solid var(--line); padding-left: 10px; }
#tree > details { margin-left: 0; border-left: 0; padding-left: 0; }
summary { cursor: pointer; font: 600 13px var(--mono); padding: 3px 0; word-break: break-all; }
summary .pid { color: var(--muted); font-weight: 400; }
.ev { font: 13px var(--mono); padding: 1px 0 1px 14px; word-break: break-all; }
.ev .v { display: inline-block; width: 6.5ch; }
.ev-write .v { color: var(--green); } .ev-delete .v { color: var(--red); } .ev-read .v { color: var(--muted); } .ev-net .v { color: var(--cyan); } .ev-op .v { color: var(--yellow); }
.ev .v { width: 7.5ch; }
.dim { color: var(--muted); } .name { color: var(--cyan); }
.fail { color: var(--yellow); } .tag { color: var(--red); font-weight: 600; }
table { width: 100%; border-collapse: collapse; font: 13px var(--mono); }
td { padding: 2px 8px 2px 0; vertical-align: top; border-bottom: 1px solid var(--line); word-break: break-all; }
td.t { color: var(--muted); white-space: nowrap; } td.k { white-space: nowrap; }
.k-write { color: var(--green); } .k-delete { color: var(--red); } .k-net { color: var(--cyan); } .k-read { color: var(--muted); } .k-exec { font-weight: 700; } .k-op { color: var(--yellow); }
[hidden] { display: none !important; }
.hint { color: var(--muted); font-size: 12px; margin-top: 8px; }
</style>
</head>
<body>
<main>
  <h1 id="cmd">__TITLE__</h1>
  <div class="meta" id="meta"></div>
  <div class="notes" id="notes"></div>
  <section class="card findings"><h2>Findings</h2><div id="findings"></div></section>
  <section class="card" id="ioc-card" hidden><h2>Indicators (IOC)</h2><div id="iocs"></div></section>

  <div class="bar">
    <div class="tabs" role="group" aria-label="View">
      <button id="tab-tree" aria-pressed="true">Process tree</button><button id="tab-time" aria-pressed="false">Timeline</button>
    </div>
    <input type="search" id="q" placeholder="filter: path, process, address..." aria-label="Filter">
    <label><input type="checkbox" id="f-write" checked> write</label>
    <label><input type="checkbox" id="f-delete" checked> delete</label>
    <label><input type="checkbox" id="f-read" checked> read</label>
    <label><input type="checkbox" id="f-net" checked> net</label>
    <label><input type="checkbox" id="f-op" checked> other ops</label>
    <label><input type="checkbox" id="f-noise"> system noise</label>
  </div>

  <section id="tree"></section>
  <section id="timeline" hidden><table><tbody id="tl"></tbody></table></section>
  <p class="hint" id="hint"></p>
</main>

<script type="application/json" id="data">__DATA__</script>
<script>
(function () {
  var D = JSON.parse(document.getElementById('data').textContent);

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function fmtT(ns) { return ns < 1e9 ? '+' + (ns / 1e6).toFixed(1) + 'ms' : '+' + (ns / 1e9).toFixed(3) + 's'; }
  function human(n) {
    if (n < 1024) return n + ' B';
    var u = ['KiB', 'MiB', 'GiB', 'TiB'], i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(1) + ' ' + u[i];
  }
  function failNote(s) {
    if (!s.failed) return '';
    return s.failed === s.count ? 'failed: ' + s.error : s.failed + ' failed: ' + s.error;
  }
  function execLine(e) {
    var parts = [e.path].concat((e.args || []).slice(1));
    if (e.args_truncated) parts.push('...');
    return parts.join(' ');
  }
  function span(cls, text) { return el('span', cls, text); }

  var total = 0, pids = 0;
  (function count(list) { list.forEach(function (p) { pids++; (p.children && count(p.children)); }); })(D.processes || []);
  var meta = document.getElementById('meta');
  meta.appendChild(el('span', 'badge sev-' + (D.verdict === 'none' ? 'none' : D.verdict), 'verdict: ' + D.verdict));
  [['', D.status], ['', (D.duration_ms / 1000).toFixed(3) + ' s'], ['', pids + ' processes']].forEach(function (x, i) {
    if (i) meta.appendChild(document.createTextNode('  ·  '));
    meta.appendChild(el('b', '', x[1]));
  });
  document.title = 'sus: ' + D.command.join(' ');
  document.getElementById('notes').textContent = (D.notes || []).join('  ·  ');

  var fbox = document.getElementById('findings');
  if (!D.findings || !D.findings.length) {
    fbox.appendChild(el('div', 'none', 'No findings. Heuristics only: absence is not proof of safety.'));
  } else {
    var lastCat = null, ul = null;
    D.findings.forEach(function (f) {
      if (f.category !== lastCat) {
        lastCat = f.category;
        fbox.appendChild(el('h3', 'sev-' + f.severity, f.category));
        ul = el('ul');
        fbox.appendChild(ul);
      }
      var li = el('li');
      li.appendChild(span('sev-' + f.severity, '[' + f.tag + '] '));
      li.appendChild(document.createTextNode(f.text));
      ul.appendChild(li);
    });
  }

  function copyText(text, btn) {
    var done = function () { var old = btn.textContent; btn.textContent = 'copied'; setTimeout(function () { btn.textContent = old; }, 1200); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }
  function fallbackCopy(text) {
    var t = document.createElement('textarea');
    t.value = text; document.body.appendChild(t); t.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(t);
  }
  var ioc = D.iocs || {};
  var groups = [
    ['Domains', ioc.domains || []],
    ['IP addresses', ioc.ips || []],
    ['Sockets', ioc.unix_sockets || []],
    ['Files (sha256  path)', (ioc.files || []).map(function (f) { return f.sha256 + '  ' + f.path; })]
  ];
  var iocBox = document.getElementById('iocs'), anyIoc = false;
  groups.forEach(function (g) {
    if (!g[1].length) return;
    anyIoc = true;
    var wrap = el('div', 'ioc-group');
    var h = el('h3', '', g[0] + ' (' + g[1].length + ')');
    var btn = el('button', 'copy', 'copy');
    btn.addEventListener('click', function () { copyText(g[1].join('\n'), btn); });
    h.appendChild(btn);
    wrap.appendChild(h);
    wrap.appendChild(el('pre', '', g[1].join('\n')));
    iocBox.appendChild(wrap);
  });
  if (anyIoc) document.getElementById('ioc-card').hidden = false;

  var tree = document.getElementById('tree');
  function row(kind, key, s) {
    var li = el('div', 'ev ev-' + kind);
    li.dataset.kind = kind;
    li.dataset.noise = s.noise && !s.tag ? '1' : '0';
    var verb = kind, text = key;
    if (kind === 'op') {
      var sp = key.indexOf(' ');
      verb = key.slice(0, sp);
      text = key.slice(sp + 1);
    }
    var name = '';
    if (kind === 'net' || verb === 'bind' || verb === 'send') {
      var host = text.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
      name = (D.dns && D.dns[host]) || (D.resolved && D.resolved[host] ? '~' + D.resolved[host] : '');
    }
    li.dataset.text = (verb + ' ' + text + ' ' + name).toLowerCase();
    li.appendChild(span('v', verb));
    li.appendChild(document.createTextNode(text));
    if (name) li.appendChild(span('name', ' (' + name + ')'));
    if (s.count > 1) li.appendChild(span('dim', '  x' + s.count));
    var f = s.file;
    if (f) {
      if (f.gone) li.appendChild(span('dim', '  (gone afterwards)'));
      else if (f.kind === 'symlink') li.appendChild(span('dim', '  -> ' + f.link));
      else {
        var info = human(f.size) + (f.sha256 ? '  sha256:' + f.sha256.slice(0, 12) : '');
        var si = span('dim', '  ' + info);
        if (f.sha256) si.title = f.sha256;
        li.appendChild(si);
        if (f.setuid) li.appendChild(span('tag', '  [SETUID]'));
        else if (f.kind === 'elf') li.appendChild(span('tag', '  [ELF binary]'));
        else if (f.kind === 'script' && f.executable) li.appendChild(span('fail', '  [executable script]'));
      }
    }
    var fn = failNote(s);
    if (fn) li.appendChild(span('fail', '  (' + fn + ')'));
    if (s.tag) li.appendChild(span('tag', '  [' + s.tag + ']'));
    return li;
  }
  function addRows(box, kind, map) {
    Object.keys(map || {}).sort().forEach(function (k) { box.appendChild(row(kind, k, map[k])); });
  }
  function node(p) {
    var d = el('details');
    d.open = true;
    var s = el('summary');
    var execs = p.executed || [];
    if (!execs.length) s.appendChild(document.createTextNode(p.comm + ' (forked)'));
    execs.forEach(function (e, i) {
      if (i) s.appendChild(document.createTextNode(' → '));
      s.appendChild(document.createTextNode(execLine(e)));
      if (e.anomalies && e.anomalies.length) s.appendChild(span('anom', ' [' + e.anomalies.join('; ') + ']'));
      if (e.sha256) {
        var h = span('dim', ' sha256:' + e.sha256.slice(0, 12));
        h.title = e.sha256;
        s.appendChild(h);
      }
    });
    s.appendChild(span('pid', '  [' + p.pid + ']'));
    d.appendChild(s);
    var box = el('div');
    addRows(box, 'write', p.written);
    addRows(box, 'delete', p.deleted);
    addRows(box, 'op', p.operations);
    addRows(box, 'read', p.read);
    addRows(box, 'net', p.connections);
    d.appendChild(box);
    (p.children || []).forEach(function (c) { d.appendChild(node(c)); });
    return d;
  }
  (D.processes || []).forEach(function (p) { tree.appendChild(node(p)); });

  var tl = document.getElementById('tl');
  function group(kind) {
    if (kind === 'exec' || kind === 'write' || kind === 'delete' || kind === 'read' || kind === 'net') return kind;
    if (kind === 'stat') return 'read';
    if (kind === 'dns' || kind === 'resolve') return 'net';
    return 'op';
  }
  (D.timeline || []).forEach(function (e) {
    var tr = el('tr');
    var g = group(e.kind);
    tr.dataset.kind = g;
    tr.dataset.noise = e.noise && !e.tag ? '1' : '0';
    tr.dataset.text = (e.kind + ' ' + e.text + ' ' + e.proc + ' ' + e.pid).toLowerCase();
    tr.appendChild(el('td', 't', fmtT(e.t_ns)));
    tr.appendChild(el('td', 'k k-' + g, e.kind));
    var td = el('td', '', e.text);
    if (e.failed) td.appendChild(span('fail', '  (failed)'));
    if (e.tag) td.appendChild(span('tag', '  [' + e.tag + ']'));
    tr.appendChild(td);
    tr.appendChild(el('td', 't', e.proc + ' ' + e.pid));
    tl.appendChild(tr);
  });

  var q = document.getElementById('q');
  var kinds = ['write', 'delete', 'read', 'net', 'op'];
  function apply() {
    var needle = q.value.trim().toLowerCase();
    var on = {};
    kinds.forEach(function (k) { on[k] = document.getElementById('f-' + k).checked; });
    var noise = document.getElementById('f-noise').checked;
    var shown = 0;
    document.querySelectorAll('[data-kind]').forEach(function (n) {
      var k = n.dataset.kind;
      var ok = (k === 'exec' || on[k]) &&
        (noise || n.dataset.noise !== '1') &&
        (!needle || n.dataset.text.indexOf(needle) !== -1);
      n.hidden = !ok;
      if (ok) shown++;
    });
    document.getElementById('hint').textContent = shown + ' entries shown';
  }
  ['q', 'f-write', 'f-delete', 'f-read', 'f-net', 'f-op', 'f-noise'].forEach(function (id) {
    document.getElementById(id).addEventListener(id === 'q' ? 'input' : 'change', apply);
  });

  function tab(which) {
    document.getElementById('tree').hidden = which !== 'tree';
    document.getElementById('timeline').hidden = which !== 'time';
    document.getElementById('tab-tree').setAttribute('aria-pressed', which === 'tree');
    document.getElementById('tab-time').setAttribute('aria-pressed', which === 'time');
  }
  document.getElementById('tab-tree').addEventListener('click', function () { tab('tree'); });
  document.getElementById('tab-time').addEventListener('click', function () { tab('time'); });

  apply();
})();
</script>
</body>
</html>
`
