"""The dashboard page: its markup under the strict policy, and its script's behaviour.

The script runs under Node against a small fake DOM built from the page's own
markup, with fetch answered by an in-memory stand-in for the API. Nothing here
contacts a router or a server.
"""

import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "cudy_manager" / "dashboard.html"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is needed to run the dashboard script")

HARNESS = r"""
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));

function compound(selector) {
  const match = selector.match(/^([a-zA-Z0-9*]+)?(.*)$/);
  const tag = match[1] && match[1] !== '*' ? match[1].toUpperCase() : null;
  const parts = match[2].match(/#[\w-]+|\.[\w-]+|\[[^\]]+\]/g) || [];
  return (el) => {
    if (!(el instanceof El)) return false;
    if (tag && el.tagName !== tag) return false;
    return parts.every((part) => {
      if (part[0] === '#') return el.id === part.slice(1);
      if (part[0] === '.') return el.classList.contains(part.slice(1));
      const inner = part.slice(1, -1);
      const eq = inner.indexOf('=');
      if (eq < 0) return el.hasAttribute(inner);
      return el.getAttribute(inner.slice(0, eq)) === inner.slice(eq + 1).replace(/^["']|["']$/g, '');
    });
  };
}
function selectorGroups(selector) {
  return selector.split(',').map((group) => group.trim().split(/\s+/).map(compound));
}
function matchesGroup(el, steps) {
  if (!steps[steps.length - 1](el)) return false;
  let index = steps.length - 2;
  for (let node = el.parentNode; index >= 0 && node; node = node.parentNode) if (steps[index](node)) index--;
  return index < 0;
}

const NON_BUBBLING = new Set(['close', 'cancel', 'focus', 'blur']);
// The focused control; document.activeElement reads it as a browser would.
let focusedNode = null;
function blurInside(node) { if (focusedNode && node.contains(focusedNode)) focusedNode = null; }
let documentNode = null;
let windowNode = null;
let htmlRoot = null;

class El {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.attrs = {};
    for (const [key, value] of Object.entries(attrs)) this.attrs[key] = String(value);
    this.childNodes = [];
    this.parentNode = null;
    this.listeners = {};
    this.style = {};
    this._value = this.attrs.value !== undefined ? this.attrs.value : '';
    this.defaultValue = this._value;
    this._valueSet = false;
    this.checked = 'checked' in this.attrs;
    this.defaultChecked = this.checked;
    this._disabled = 'disabled' in this.attrs;
    this.returnValue = '';
    this.files = [];
  }
  get disabled() { return this._disabled; }
  // A browser's focus fixup: a focused control that is disabled loses focus to the body.
  set disabled(value) {
    this._disabled = Boolean(value);
    if (this._disabled && focusedNode === this) focusedNode = null;
  }
  get id() { return this.attrs.id || ''; }
  set id(value) { this.attrs.id = String(value); }
  get className() { return this.attrs.class || ''; }
  set className(value) { this.attrs.class = String(value); }
  get classList() {
    const self = this;
    const list = () => self.className.split(/\s+/).filter(Boolean);
    return {
      contains: (name) => list().includes(name),
      add: (...names) => { self.className = [...new Set([...list(), ...names])].join(' '); },
      remove: (...names) => { self.className = list().filter((x) => !names.includes(x)).join(' '); },
      toggle: (name, force) => {
        const want = force === undefined ? !list().includes(name) : Boolean(force);
        self.className = (want ? [...new Set([...list(), name])] : list().filter((x) => x !== name)).join(' ');
        return want;
      },
    };
  }
  get hidden() { return 'hidden' in this.attrs; }
  set hidden(value) { if (value) this.attrs.hidden = ''; else delete this.attrs.hidden; }
  get open() { return 'open' in this.attrs; }
  get title() { return this.attrs.title || ''; }
  set title(value) { this.attrs.title = String(value); }
  get type() {
    if (this.attrs.type) return this.attrs.type;
    return this.tagName === 'BUTTON' ? 'submit' : this.tagName === 'INPUT' ? 'text' : '';
  }
  set type(value) { this.attrs.type = String(value); }
  get name() { return this.attrs.name || ''; }
  get dataset() {
    const el = this;
    const attr = (prop) => 'data-' + String(prop).replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
    return new Proxy({}, {
      get: (_, prop) => (typeof prop === 'string' && attr(prop) in el.attrs ? el.attrs[attr(prop)] : undefined),
      set: (_, prop, value) => { el.attrs[attr(prop)] = String(value); return true; },
      deleteProperty: (_, prop) => { delete el.attrs[attr(prop)]; return true; },
      has: (_, prop) => attr(prop) in el.attrs,
    });
  }
  get value() {
    if (this.tagName === 'SELECT') {
      const options = this.options;
      if (this._valueSet) { const hit = options.find((o) => o.value === this._value); return hit ? hit.value : ''; }
      const chosen = options.find((o) => 'selected' in o.attrs) || options[0];
      return chosen ? chosen.value : '';
    }
    if (this.tagName === 'OPTION') return this.attrs.value !== undefined ? this.attrs.value : this.textContent;
    if (this.tagName === 'TEXTAREA' && !this._valueSet) return this.textContent;
    return this._value;
  }
  set value(value) {
    this._value = String(value);
    this._valueSet = true;
    if (this.type === 'file' && this._value === '') this.files = [];
  }
  get options() { return this.descendants().filter((node) => node.tagName === 'OPTION'); }
  get children() { return this.childNodes.filter((node) => node instanceof El); }
  get textContent() {
    return this.childNodes.map((node) => (typeof node === 'string' ? node : node.textContent)).join('');
  }
  set textContent(value) { this.detachAll(); this.childNodes = [String(value)]; }
  set innerHTML(_) { throw new Error('innerHTML is not allowed: the page must insert text with textContent'); }
  get innerHTML() { throw new Error('innerHTML is not allowed'); }
  // As in a browser, taking the focused control out of the page blurs it, even if it is put back.
  detachAll() {
    for (const node of this.childNodes) if (node instanceof El) { node.parentNode = null; blurInside(node); }
  }
  adopt(node) {
    if (node instanceof El) { if (node.parentNode) node.remove(); node.parentNode = this; return node; }
    return String(node);
  }
  append(...nodes) { for (const node of nodes) this.childNodes.push(this.adopt(node)); }
  prepend(...nodes) { this.childNodes.unshift(...nodes.map((node) => this.adopt(node))); }
  replaceChildren(...nodes) { this.detachAll(); this.childNodes = []; this.append(...nodes); }
  remove() {
    if (!this.parentNode) return;
    this.parentNode.childNodes = this.parentNode.childNodes.filter((n) => n !== this);
    this.parentNode = null;
    blurInside(this);
  }
  contains(node) { for (let n = node; n; n = n.parentNode) if (n === this) return true; return false; }
  setAttribute(key, value) {
    const text = String(value);
    this.attrs[key] = text;
    if (key === 'disabled') this.disabled = true;
    if (key === 'checked') { this.checked = true; this.defaultChecked = true; }
    if (key === 'value' && !this._valueSet) { this._value = text; this.defaultValue = text; }
  }
  getAttribute(key) { return key in this.attrs ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; if (key === 'disabled') this.disabled = false; }
  hasAttribute(key) { return key === 'disabled' ? this.disabled : key in this.attrs; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); }
  dispatch(type, extra = {}) {
    const event = Object.assign({
      type, target: this, currentTarget: null, defaultPrevented: false, stopped: false,
      preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; },
    }, extra);
    const path = [];
    for (let node = this; node; node = node.parentNode) path.push(node);
    if (path[path.length - 1] === htmlRoot) path.push(documentNode, windowNode);
    const results = [];
    for (const node of (NON_BUBBLING.has(type) ? [this] : path)) {
      event.currentTarget = node;
      for (const fn of (node.listeners[type] || []).slice()) results.push(fn.call(node, event));
      if (event.stopped) break;
    }
    return { event, results };
  }
  descendants() {
    const out = [];
    const walk = (node) => { for (const child of node.children) { out.push(child); walk(child); } };
    walk(this);
    return out;
  }
  matches(selector) { return selectorGroups(selector).some((steps) => matchesGroup(this, steps)); }
  closest(selector) {
    for (let node = this; node instanceof El; node = node.parentNode) if (node.matches(selector)) return node;
    return null;
  }
  querySelectorAll(selector) {
    const groups = selectorGroups(selector);
    return this.descendants().filter((el) => groups.some((steps) => matchesGroup(el, steps)));
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  showModal() {
    if (this.open) throw new Error('InvalidStateError: the dialog is already open');
    this.attrs.open = '';
    this.opener = documentNode.activeElement;
  }
  close(value) {
    if (!this.open) return;
    delete this.attrs.open;
    // A modal dialog hands focus back to what had it when the dialog opened.
    const opener = this.opener;
    this.opener = null;
    if (opener && opener !== body) opener.focus();
    if (value !== undefined) this.returnValue = String(value);
    this.dispatch('close');
  }
  focus() { if (!this.disabled && htmlRoot.contains(this)) focusedNode = this; }
  blur() {}
  select() {}
  click() {
    if (this.disabled) return Promise.resolve([]);
    if (['BUTTON', 'INPUT', 'SELECT', 'A'].includes(this.tagName)) this.focus();
    const toggles = this.tagName === 'INPUT' && (this.type === 'checkbox' || this.type === 'radio');
    const before = this.checked;
    if (toggles) this.checked = this.type === 'radio' ? true : !this.checked;
    const { event, results } = this.dispatch('click');
    if (toggles) {
      if (event.defaultPrevented) this.checked = before;
      else if (this.checked !== before) { this.dispatch('input'); results.push(...this.dispatch('change').results); }
    } else if (!event.defaultPrevented && this.tagName === 'BUTTON') {
      const form = this.closest('form');
      if (form && this.type === 'submit') results.push(harness.submit(form, this));
      else if (form && this.type === 'reset') form.reset();
    }
    return Promise.all(results);
  }
  reset() {
    const { event } = this.dispatch('reset');
    if (event.defaultPrevented) return;
    for (const node of this.descendants()) {
      if (!['INPUT', 'SELECT', 'TEXTAREA'].includes(node.tagName)) continue;
      node._value = node.defaultValue; node._valueSet = false; node.checked = node.defaultChecked;
      if (node.type === 'file') node.files = [];
    }
  }
}

function build(node) {
  const el = new El(node.tag, node.attrs);
  for (const child of node.children) el.append(typeof child === 'string' ? child : build(child));
  return el;
}

htmlRoot = new El('html');
const body = build(input.tree);
htmlRoot.append(body);
const listenable = {
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn); },
};
documentNode = Object.assign(Object.create(listenable), {
  listeners: {}, hidden: false, documentElement: htmlRoot, body,
  getElementById: (id) => htmlRoot.descendants().find((node) => node.id === id) || null,
  querySelector: (selector) => htmlRoot.querySelector(selector),
  querySelectorAll: (selector) => htmlRoot.querySelectorAll(selector),
  createElement: (tag) => new El(tag),
  contains: (node) => htmlRoot.contains(node),
});
// As in a browser: once the focused control leaves the document, focus is on the body.
Object.defineProperty(documentNode, 'activeElement', {
  get: () => (focusedNode && htmlRoot.contains(focusedNode) ? focusedNode : body),
});
windowNode = Object.assign(Object.create(listenable), { listeners: {} });
const fireWindow = (type) => { for (const fn of (windowNode.listeners[type] || []).slice()) fn({ type }); };

let now = 0;
let timerSeq = 0;
const timers = new Map();
const flush = async () => { for (let i = 0; i < 60; i++) await new Promise((resolve) => setImmediate(resolve)); };
const requests = [];
const errors = [];
process.on('unhandledRejection', (error) => errors.push(String((error && error.stack) || error)));

const location = {
  href: 'http://skyrouter.test/',
  _hash: input.hash || '',
  get hash() { return this._hash; },
  set hash(value) {
    let next = String(value);
    if (next && next[0] !== '#') next = '#' + next;
    if (next === '#') next = '';
    if (next === this._hash) return;
    this._hash = next;
    Promise.resolve().then(() => fireWindow('hashchange'));
  },
};
const storage = new Map();

const db = {
  csrf: 't1', me: { actor: 'Skybre staff', mode: 'standalone' }, devices: [], acs: null, acsDevices: [], acsNew: [],
  acsTotal: null, acsDetail: {}, jobs: [], plans: [], activity: [], nextBefore: null, records: [], library: [],
};
const ok = (body, status = 200) => ({ status, body });
const OFF = { detail: 'TR-069 management is not configured', configured: false };
function defaultReply(req) {
  const [base, query = ''] = req.path.split('?');
  const params = new URLSearchParams(query);
  const get = req.method === 'GET';
  if (base === '/api/csrf') return ok({ csrf_token: db.csrf });
  if (base === '/api/me') return ok(db.me);
  if (base === '/api/devices' && get) {
    const online = db.devices.filter((d) => (d.status || {}).online === true).length;
    const summary = { total_devices: db.devices.length, online, offline: db.devices.length - online };
    return ok({ devices: db.devices, summary });
  }
  if (base.startsWith('/api/acs') && !db.acs) return ok(OFF, 503);
  if (base === '/api/acs') return ok(db.acs);
  if (base === '/api/acs/devices' && get) {
    const tag = params.get('tag');
    const all = db.acsDevices.concat(db.acsNew);
    const list = tag ? all.filter((d) => (d.tags || []).includes(tag)) : all;
    return ok({ devices: list, total: db.acsTotal == null ? list.length : db.acsTotal });
  }
  const detail = base.match(/^\/api\/acs\/devices\/([^/]+)$/);
  if (detail && get) return ok({ device: db.acsDetail[decodeURIComponent(detail[1])] || {} });
  if (base === '/api/acs/jobs' && get) return ok({ jobs: db.jobs });
  if (base === '/api/acs/firmware' && get) return ok({ firmware: db.library });
  if (base === '/api/maintenance/plans' && get) return ok({ plans: db.plans });
  if (base === '/api/activity') return ok({ entries: db.activity, next_before: db.nextBefore });
  if (base === '/api/setup/records' && get) return ok({ records: db.records });
  return ok({});
}

async function fetch(path, options = {}) {
  let sent = null;
  if (typeof options.body === 'string') {
    try { sent = JSON.parse(options.body); } catch (_) { sent = options.body; }
  } else if (options.body) sent = { file: options.body.name, size: options.body.size };
  const headers = Object.assign({}, options.headers || {});
  const record = { path, method: options.method || 'GET', headers, body: sent };
  requests.push(record);
  const reply = (await harness.handler(record)) || defaultReply(record);
  if (reply.unreachable) throw new TypeError('Failed to fetch');
  const status = reply.status || 200;
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => {
      if (reply.body === undefined) throw new SyntaxError('not JSON');
      return JSON.parse(JSON.stringify(reply.body));
    },
  };
}

const byId = (id) => documentNode.getElementById(id);
const rowButton = (tr) => (tr.children[0] ? tr.children[0].querySelector('.row-btn') : null);
const harness = {
  db, requests, errors, flush, storage, storageBlocked: false, dark: false, clipboard: null,
  handler: () => undefined,
  deferred() { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; },
  async advance(ms) {
    const target = now + ms;
    for (;;) {
      let next = null;
      for (const [id, timer] of timers) if (timer.at <= target && (!next || timer.at < next[1].at)) next = [id, timer];
      if (!next) break;
      timers.delete(next[0]);
      now = next[1].at;
      next[1].fn();
      await flush();
    }
    now = target;
    await flush();
  },
  submit(form, submitter = null) {
    const { event, results } = form.dispatch('submit', { submitter });
    const dialog = form.closest('dialog');
    if (!event.defaultPrevented && form.getAttribute('method') === 'dialog' && dialog) {
      dialog.close(submitter ? submitter.value : undefined);
    }
    return Promise.all(results);
  },
  escape(dialog) { const { event } = dialog.dispatch('cancel'); if (!event.defaultPrevented) dialog.close(); },
  key(key) { return (documentNode.activeElement || body).dispatch('keydown', { key }); },
  async go(hash) { location.hash = hash; await flush(); },
  async type(node, value) { node.value = value; await Promise.all(node.dispatch('input').results); },
  async choose(node, value) { node.value = value; await Promise.all(node.dispatch('change').results); await flush(); },
  // Not awaited: a handler may be waiting on a confirmation the scenario gives next.
  async press(node) { if (!node) throw new Error('press: no such control'); node.click(); await flush(); },
  button: (node, label) => node.querySelectorAll('button').find((b) => b.textContent.trim() === label) || null,
  buttons: (node) => node.querySelectorAll('button').map((b) => b.textContent.trim()),
  rows: (id = 'rows') => byId(id).children.map((tr) => tr.children.map((td) => td.textContent.trim())),
  row: (name) => byId('rows').children.find((tr) => rowButton(tr) && rowButton(tr).textContent === name) || null,
  async open(name) {
    const row = harness.row(name);
    if (!row) throw new Error('no row for ' + name);
    await rowButton(row).click();
    await flush();
  },
  toasts: () => byId('toasts').children.map((t) => ({
    kind: t.dataset.kind, title: t.children[0].children[1].textContent, text: t.children[1].textContent,
  })),
  sent: (method, prefix) => requests.filter((r) => r.method === method && r.path.startsWith(prefix)).map((r) => ({
    path: r.path, body: r.body, csrf: r.headers['X-CSRF-Token'] || null, type: r.headers['Content-Type'] || null,
  })),
  paths: () => requests.map((r) => `${r.method} ${r.path}`),
};

const blocked = () => { if (harness.storageBlocked) throw new Error('SecurityError: storage is blocked'); };
const context = vm.createContext({
  document: documentNode, window: windowNode, location, fetch, harness, console, byId,
  URLSearchParams, URL, TextEncoder,
  setTimeout: (fn, ms = 0) => { const id = ++timerSeq; timers.set(id, { at: now + ms, fn }); return id; },
  clearTimeout: (id) => { timers.delete(id); },
  matchMedia: (query) => ({
    matches: Boolean(harness.dark) && query.includes('dark'), media: query,
    addEventListener() {}, removeEventListener() {},
  }),
  localStorage: {
    getItem: (key) => { blocked(); return storage.has(key) ? storage.get(key) : null; },
    setItem: (key, value) => { blocked(); storage.set(key, String(value)); },
    removeItem: (key) => { storage.delete(key); },
  },
  navigator: { clipboard: { writeText: async (text) => { harness.clipboard = text; } } },
});

let finished = false;
process.on('beforeExit', () => {
  if (finished) return;
  process.stderr.write('the scenario never finished: it awaits something nothing resolves');
  process.exit(1);
});
(async () => {
  if (input.setup) vm.runInContext(input.setup, context);
  vm.runInContext(input.script, context);
  await flush();
  const result = await vm.runInContext('(async () => {' + input.scenario + '\n})()', context);
  await flush();
  finished = true;
  const outcome = { result: result === undefined ? null : result, requests, errors, href: location.href };
  process.stdout.write(JSON.stringify(outcome));
})().catch((error) => { process.stderr.write(String((error && error.stack) || error)); process.exit(1); });
"""


def dashboard_markup() -> tuple[dict, str]:
    """Parse dashboard.html's body into a plain tree, and pull out its script."""
    void = {"input", "meta", "br", "img", "link", "hr"}

    class Builder(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.root: dict = {"tag": "body", "attrs": {}, "children": []}
            self.stack = [self.root]
            self.in_body = False
            self.in_script = False
            self.script: list[str] = []

        def handle_starttag(self, tag, attrs):
            if tag == "body":
                self.in_body = True
            elif tag == "script":
                self.in_script = True
            elif self.in_body:
                node = {"tag": tag, "attrs": {key: value or "" for key, value in attrs}, "children": []}
                self.stack[-1]["children"].append(node)
                if tag not in void:
                    self.stack.append(node)

        def handle_endtag(self, tag):
            if tag == "script":
                self.in_script = False
            elif self.in_body and tag not in void and tag != "body":
                while len(self.stack) > 1 and self.stack.pop()["tag"] != tag:
                    pass

        def handle_data(self, data):
            if self.in_script:
                self.script.append(data)
            elif self.in_body:
                self.stack[-1]["children"].append(data)

    builder = Builder()
    builder.feed(PAGE.read_text(encoding="utf-8"))
    return builder.root, "".join(builder.script)


def run_page(tmp_path: Path, scenario: str, setup: str = "", hash_: str = "") -> dict:
    """Load the page with ``setup`` run first, then run ``scenario``; times read as UTC."""
    tree, script = dashboard_markup()
    harness = tmp_path / "dashboard_ui_harness.js"
    harness.write_text(HARNESS, encoding="utf-8")
    payload = json.dumps({"tree": tree, "script": script, "setup": setup, "scenario": scenario, "hash": hash_})
    assert NODE is not None
    completed = subprocess.run(
        [NODE, str(harness)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "TZ": "UTC"},
    )
    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout)
    assert outcome["errors"] == [], outcome["errors"]
    return outcome


def reply(body: dict, status: int = 200) -> str:
    """A JS reply literal for harness.handler."""
    return json.dumps({"status": status, "body": body})


def contrast(first: str, second: str) -> float:
    """The WCAG contrast ratio of two #RRGGBB colours."""

    def luminance(colour: str) -> float:
        channels = [int(colour.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        red, green, blue = (c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
        return 0.2126 * red + 0.7152 * green + 0.0722 * blue

    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def theme_tokens(page: str) -> dict[str, dict[str, str]]:
    """The colour tokens of a page's light :root block and its forced dark one."""
    blocks = {"light": r":root \{(.*?)\n\}", "dark": r':root\[data-theme="dark"\] \{(.*?)\n\}'}
    found = {}
    for name, pattern in blocks.items():
        match = re.search(pattern, page, re.S)
        assert match is not None, name
        found[name] = dict(re.findall(r"--([\w-]+):\s*(#[0-9A-Fa-f]{6})\b", match.group(1)))
    return found


# Three direct routers (online, login refused, offline), two adopted TR-069 routers
# (online on two bands, offline) and two TR-069 routers still waiting to be adopted.
FLEET = r"""
const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString();
harness.db.devices = [
  {id: 'hk', vendor: 'cudy', host: '192.168.3.247', username: 'admin', model: 'Cudy AP1300', transport: 'web',
   enabled: true, metadata: {name: 'Hennenman kantoor', customer: 'Skybre office'}, last_seen: minutesAgo(0),
   status: {online: true, firmware: '2.5.25', uptime_seconds: 300, checked_at: minutesAgo(0)}},
  {id: 't3', vendor: 'tplink', host: '192.168.0.1', username: 'admin', model: 'TL-WR840N', transport: 'web',
   enabled: true, metadata: {name: 'Tower 3 office'}, last_seen: minutesAgo(60),
   status: {online: null, reason: 'credentials_rejected', error: 'the router refused the login'}},
  {id: 'td', vendor: 'tenda', host: '192.168.5.1', username: 'admin', model: 'Tenda AC6', transport: 'web',
   enabled: true, metadata: {name: 'Tenda shop', radio: '5G'}, last_seen: minutesAgo(180),
   status: {online: false, error: 'timed out'}},
];
harness.db.acs = {configured: true, reachable: true, version: '1.2.16', error: null,
  bootstrap: {installed: true, drift: [], seeded_presets: []}, channel_faults: [], problems: [], jobs: {active: 0}};
harness.db.acsDevices = [
  {acs_id: '80AFCA-WR3000-AB%2D1', manufacturer: 'Cudy', model: 'WR3000', serial: 'AB-1', firmware: '2.3.8',
   data_model: 'tr181', online: true, last_inform: minutesAgo(2), inform_interval: 300, tags: [],
   customer: '#1042 Customer A',
   wifi: [{band: '2.4GHz', band_source: 'reported', ssid: 'CustomerA-WiFi', enabled: true},
          {band: '5GHz', band_source: 'guessed', ssid: 'CustomerA-WiFi-5G', enabled: true}]},
  {acs_id: '80AFCA-WR1300-CD1', manufacturer: 'Cudy', model: 'WR1300', serial: 'CD1', firmware: '2.2.4',
   data_model: 'tr098', online: false, last_inform: minutesAgo(200), inform_interval: 300, tags: ['shop'],
   wifi: [{band: '2.4GHz', band_source: 'reported', ssid: 'CustomerD-2G', enabled: true}]},
];
harness.db.acsNew = [
  {acs_id: '80AFCA-WR3000-NEW1', model: 'WR3000', serial: 'NEW1', tags: ['skybre_new'], online: true, wifi: []},
  {acs_id: '80AFCA-M3000-NEW2', model: 'M3000', serial: 'NEW2', tags: ['skybre_new'], online: true, wifi: []},
];
"""
ACS_ID = "80AFCA-WR3000-AB%2D1"
# The ID as it appears in a request path: encodeURIComponent turns its % into %25.
ACS_PATH = "/api/acs/devices/80AFCA-WR3000-AB%252D1"
NO_ACS = FLEET + "harness.db.acs = null;"
JSON_TYPE = "application/json"


def job(state: str, **extra) -> dict:
    active = state in ("queued", "contacting_router", "waiting_for_checkin")
    return {"id": "j1", "acs_id": ACS_ID, "kind": "wifi", "state": state, "message": "", "expected_by": None,
            "terminal": not active, "done": not active, **extra}


def sent(path: str, body, csrf: str | None = "t1", kind: str | None = JSON_TYPE) -> dict:
    """One request as harness.sent reports it."""
    return {"path": path, "body": body, "csrf": csrf, "type": kind}


# --- the markup ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8")


class TestMarkup:
    def test_one_script_carrying_the_nonce_placeholder(self, page: str):
        assert page.count("<script") == 1
        assert '<script nonce="__CSP_NONCE__">' in page

    def test_no_inline_event_handlers_and_no_html_sinks(self, page: str):
        # Inline handlers need 'unsafe-inline' in script-src, which the policy omits.
        assert not re.search(r"""\son[a-z]+\s*=\s*["']""", page), "an inline event handler would be blocked"
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert sink not in page, sink

    def test_every_asset_is_same_origin(self, page: str):
        references = re.findall(r"""\s(?:src|href)=["']([^"']+)["']""", page)
        assert "/assets/skybre-icon.png" in references
        assert "/favicon.ico" in references
        for reference in references:
            assert reference.startswith(("/", "#")), reference
        assert "@import" not in page and "url(" not in page

    def test_the_skybre_tokens_and_both_themes_match_the_prototype(self, page: str):
        light = re.search(r":root \{(.*?)\n\}", page, re.S).group(1)
        # The one departure: the prototype's sky-blue ring is too faint on white (see below).
        assert "--accent: #1070B0" in light and "--bg: #F9F9F7" in light and "--focus: #1070B0" in light
        assert '@media (prefers-color-scheme: dark) {\n  :root:not([data-theme="light"]) {' in page
        forced = re.search(r':root\[data-theme="dark"\] \{(.*?)\n\}', page, re.S).group(1)
        assert "--accent: #5AA8DE" in forced and "--bg: #131312" in forced and "color-scheme: dark" in forced
        assert "body { margin: 0; background: var(--bg);" in page

    def test_accessibility_basics(self, page: str):
        assert '<a class="skip" href="#main">Skip to content</a>' in page
        assert 'id="main" tabindex="-1"' in page
        assert ":focus-visible { outline: 3px solid var(--focus)" in page
        assert "@media (prefers-reduced-motion: reduce)" in page
        assert 'aria-label="Switch to dark mode"' in page

    def test_the_prototype_only_parts_are_gone(self, page: str):
        # The passkey is the server's to check, and Vexar integration comes later.
        assert "PASSKEY" not in page and "crypto.subtle" not in page
        assert "mode-switch" not in page and "Opened from Vexar" not in page
        assert "Thandi" not in page and "sampleClients" not in page

    def test_the_focus_ring_stands_out_on_every_surface_in_both_themes(self, page: str):
        # WCAG 1.4.11: a focus indicator needs 3:1 against what it is drawn on.
        for name, tokens in theme_tokens(page).items():
            for surface in ("surface", "bg", "subtle", "accent-soft"):
                ratio = contrast(tokens["focus"], tokens[surface])
                assert ratio >= 3, f"{name}: the focus ring is {ratio:.2f}:1 on --{surface}"

    def test_a_switched_off_plan_is_marked_rather_than_faded(self, page: str):
        # Fading the card took its labels below 4.5:1 and its switch below 3:1, though both still work.
        assert not re.search(r"\.plan\.off \{[^}]*opacity", page)
        track = re.search(r"\.switch span \{[^}]*background: var\(--([\w-]+)\)", page).group(1)
        for name, tokens in theme_tokens(page).items():
            for surface in ("surface", "subtle"):
                ratio = contrast(tokens[track], tokens[surface])
                assert ratio >= 3, f"{name}: the switched-off track is {ratio:.2f}:1 on --{surface}"

    def test_the_header_search_shows_its_focus(self, page: str):
        # The input drops its own outline to sit flush in its box, so the box carries the ring.
        assert ".top-search input { flex: 1; border: none; outline: none;" in page
        assert ".top-search:focus-within { outline: 3px solid var(--focus); outline-offset: 2px; }" in page

    def test_the_content_is_the_main_landmark(self, page: str):
        assert '<main class="content" id="main" tabindex="-1">' in page
        assert page.count("<main") == 1 and page.count("</main>") == 1

    def test_the_notes_above_the_list_cannot_push_it_off_screen(self, page: str):
        notes = re.search(r"\n\.notes \{([^}]*)\}", page).group(1)
        assert "max-height: 30vh" in notes and "overflow: auto" in notes

    def test_the_genieacs_hint_gives_way_before_the_bar_wraps(self, page: str):
        # It fits beside the bar's controls on one row only from about 1536 px.
        hides = r"@media \(max-width: (\d+)px\) \{[^@]*?\.bar-note[^{]*\{ display: none"
        widths = [int(w) for w in re.findall(hides, page)]
        assert widths and max(widths) >= 1540
        assert ".content:has(> .drawer:not([hidden])) .bar-note { display: none; }" in page

    def test_the_header_fits_a_phone(self, page: str):
        phone = re.search(r"@media \(max-width: 700px\) \{(.*?)\n\}", page, re.S).group(1)
        assert ".nav { flex: 1; min-width: 0; overflow-x: auto; }" in phone
        assert ".brand b, .brand span" in phone

    def test_the_more_menu_is_a_plain_disclosure(self, page: str):
        # role=menu promises arrow-key menu handling; a list of buttons behind aria-expanded does not.
        assert 'role="menu"' not in page and 'role="menuitem"' not in page and 'aria-haspopup="menu"' not in page
        assert '<button class="btn" type="button" id="d-more" aria-expanded="false" aria-controls="d-menu">' in page

    def test_the_acs_checkbox_is_named_by_its_title_alone(self):
        tree, _ = dashboard_markup()

        def walk(node):
            yield node
            for child in node["children"]:
                if isinstance(child, dict):
                    yield from walk(child)

        def text(node):
            return "".join(child if isinstance(child, str) else text(child) for child in node["children"])

        labels = [node for node in walk(tree) if node["tag"] == "label"]
        # A label holding a second labelable control is invalid, and names the checkbox after all of it.
        assert not [text(label) for label in labels if any(n["tag"] == "button" for n in walk(label))]
        (named,) = [label for label in labels if label["attrs"].get("for") == "c-acs"]
        assert text(named) == "TR-069 points at Skybre"
        (box,) = [node for node in walk(tree) if node["attrs"].get("id") == "c-acs"]
        assert box["attrs"]["aria-describedby"] == "c-acs-help acs-url"


# --- the router list ----------------------------------------------------------------------


@needs_node
class TestRouterList:
    def test_direct_and_managed_routers_are_merged_into_one_list(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const chips = byId('status-chips').children.map((c) => c.textContent);
            return {rows: harness.rows(), chips, pill: [byId('new-pill').hidden, byId('new-pill').textContent],
                    kindSeg: byId('kind-seg').hidden};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        rows = {row[0]: row for row in result["rows"]}
        assert list(rows) == [
            "Hennenman kantoor  Cudy AP1300",
            "Tenda shop  Tenda AC6",
            "Tower 3 office  TL-WR840N",
            # Named after the sticker, model and serial, so two routers of one model differ.
            "WR1300 · CD1  Cudy",
            "WR3000 · AB-1  Cudy",
        ]
        assert rows["Hennenman kantoor  Cudy AP1300"][1:3] == ["Skybre office", "Online"]
        assert rows["Tower 3 office  TL-WR840N"][2] == "Login refused"
        assert rows["Tenda shop  Tenda AC6"][2] == "Offline"
        assert rows["WR3000 · AB-1  Cudy"][1:4] == ["#1042 Customer A", "Online", "CustomerA-WiFi"]
        assert rows["WR1300 · CD1  Cudy"][2] == "Offline"
        # Routers still waiting to be adopted are not in the list: the pill offers them.
        assert result["chips"] == ["All5", "Online2", "Offline2", "Needs attention1", "Waiting0"]
        assert result["pill"] == [False, "2 new routers to adopt"]
        assert result["kindSeg"] is False

    def test_without_an_acs_the_tr069_parts_stay_hidden_and_unasked(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#setup');
            const managedMethod = byId('s-method').querySelector('[data-method=managed]');
            const managedTarget = byId('p-target').querySelector('[data-target=managed]');
            return {chips: byId('status-chips').children.map((c) => c.textContent), kindSeg: byId('kind-seg').hidden,
                    pill: byId('new-pill').hidden, method: managedMethod.hidden, target: managedTarget.hidden,
                    install: byId('a-install-row').hidden, library: byId('fw-library-card').hidden,
                    acsRow: byId('c-acs-row').hidden, admin: byId('s-admin').hidden, paths: harness.paths()};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["chips"] == ["All3", "Online1", "Offline1", "Needs attention1"]
        assert result["kindSeg"] and result["pill"] and result["method"] and result["target"]
        assert result["install"] and result["library"] and result["acsRow"]
        assert result["admin"] is False, "without TR-069 a router can only be reached by logging in"
        assert "GET /api/acs" in result["paths"]
        assert not any(path.startswith("GET /api/acs/") for path in result["paths"])

    def test_loading_error_retry_and_empty_states(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const loading = harness.rows()[0][0];
            harness.gate.resolve({status: 500, body: {detail: 'the config file is unreadable'}});
            await harness.flush();
            const failed = byId('rows').textContent;
            harness.handler = () => undefined;
            await harness.press(harness.button(byId('rows'), 'Try again'));
            return [loading, failed, harness.rows()[0][0]];
            """,
            setup=NO_ACS + """
            harness.db.devices = [];
            harness.gate = harness.deferred();
            harness.handler = (req) => (req.path.startsWith('/api/devices?') ? harness.gate.promise : undefined);
            """,
        )
        loading, failed, empty = outcome["result"]
        assert loading == "Loading routers…"
        assert "The routers could not be loaded: the config file is unreadable" in failed
        assert "Try again" in failed
        assert empty == "No routers yet. Program one under Setup."

    def test_status_chips_connection_filter_and_search(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const names = () => harness.rows().map((r) => r[0].split('  ')[0]);
            const chip = (id) => byId('status-chips').querySelector(`[data-status=${id}]`);
            await harness.press(chip('offline'));
            const offline = names();
            await harness.press(byId('kind-seg').querySelector('[data-kind=direct]'));
            const offlineDirect = names();
            await harness.press(chip('all'));
            const direct = names();
            await harness.press(byId('kind-seg').querySelector('[data-kind=all]'));
            await harness.type(byId('search'), 'customera');
            const bySsid = names();
            await harness.type(byId('search'), '192.168.0.1');
            const byIp = names();
            await harness.type(byId('search'), 'nothing like this');
            return {offline, offlineDirect, direct, bySsid, byIp, none: harness.rows()[0][0],
                    pressed: chip('all').getAttribute('aria-pressed')};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["offline"] == ["Tenda shop", "WR1300 · CD1"]
        assert result["offlineDirect"] == ["Tenda shop"]
        assert result["direct"] == ["Hennenman kantoor", "Tenda shop", "Tower 3 office"]
        assert result["bySsid"] == ["WR3000 · AB-1"]
        assert result["byIp"] == ["Tower 3 office"]
        assert result["none"] == "No routers match. Clear the search or the filters."
        assert result["pressed"] == "true"

    def test_a_router_name_that_looks_like_html_renders_as_text(self, tmp_path: Path):
        evil = '<img src=x onerror="alert(1)">'
        outcome = run_page(
            tmp_path,
            f"""
            const button = byId('rows').querySelector('.row-btn');
            await harness.open({json.dumps(evil)});
            return {{children: button.childNodes, images: document.querySelectorAll('img').length,
                     title: byId('d-name').textContent, filter: byId('f-router').options[1].textContent}};
            """,
            setup=NO_ACS + f"""
            harness.db.devices = [Object.assign(harness.db.devices[0], {{metadata: {{name: {json.dumps(evil)}}}}})];
            """,
        )
        result = outcome["result"]
        assert result["children"] == [evil], "the name must be one text node, not parsed markup"
        assert result["images"] == 1, "only the logo is an image"
        assert result["title"] == evil and result["filter"] == evil

    def test_the_list_is_polled_only_while_it_is_on_screen(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const reads = () => harness.requests.filter((r) => r.path.startsWith('/api/devices?')).length;
            const first = reads();
            await harness.advance(30000);
            const onScreen = reads();
            await harness.go('#activity');
            await harness.advance(60000);
            return [first, onScreen, reads()];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [1, 2, 2]


# --- the side panel -----------------------------------------------------------------------


@needs_node
class TestSidePanel:
    FIRMWARE = {"version": "2.5.25", "hardware": "AP1300 V1.1",
                "auto_update": {"enabled": True, "window_start_hour": 3, "window": "03:00-05:00"}}
    CLIENTS = [{"name": "Phone", "cells": ["1", "Phone", "10.20.10.21", "aa:bb"]}]
    HISTORY = [{"id": "e1", "at": "2026-09-28T14:04:00+00:00", "who": "Skybre staff", "router": "hk", "kind": "wifi",
                "what": "Wi-Fi password changed (2.4G, 5G)", "result": "applied"}]

    def test_tabs_load_firmware_devices_and_history_for_a_direct_router(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            const overview = byId('p-overview').textContent;
            await harness.press(byId('t-devices'));
            const devices = byId('p-devices').textContent;
            await harness.press(byId('t-history'));
            const history = byId('p-history').textContent;
            return {open: !byId('drawer').hidden, name: byId('d-name').textContent, sub: byId('d-sub').textContent,
                    overview, devices, history, selected: byId('t-history').getAttribute('aria-selected'),
                    overviewHidden: byId('p-overview').hidden, paths: harness.paths()};
            """,
            setup=NO_ACS + f"""
            harness.handler = (req) => {{
              if (req.path === '/api/devices/hk/firmware') return {reply({"firmware": self.FIRMWARE})};
              if (req.path === '/api/devices/hk/clients') return {reply({"clients": self.CLIENTS})};
              if (req.path.startsWith('/api/activity?')) return {reply({"entries": self.HISTORY, "next_before": None})};
            }};
            """,
        )
        result = outcome["result"]
        assert result["open"] and result["name"] == "Hennenman kantoor"
        assert result["sub"] == "Cudy AP1300 · Skybre office"
        assert "2.5.25" in result["overview"] and "Automatic updates on, 03:00-05:00" in result["overview"]
        assert "192.168.3.247" in result["overview"] and "Polled every 30 s" in result["overview"]
        assert "Phone" in result["devices"] and "10.20.10.21" in result["devices"]
        assert "Wi-Fi password changed (2.4G, 5G)" in result["history"]
        assert "28 Sep 14:04 · Skybre staff · Applied" in result["history"]
        assert result["selected"] == "true" and result["overviewHidden"] is True
        assert "GET /api/devices/hk/firmware" in result["paths"]
        assert "GET /api/devices/hk/clients" in result["paths"]
        assert "GET /api/activity?router=hk&limit=50" in result["paths"]

    def test_a_managed_router_reads_its_detail_and_history_under_its_acs_name(self, tmp_path: Path):
        detail = {
            "wan": {"ip": "10.20.0.42"}, "info": {"uptime": 518400},
            "wifi": [{"band": "2.4GHz", "ssid": "CustomerA-WiFi", "security": "wpa2", "clients": 4, "enabled": True},
                     {"band": "5GHz", "ssid": "CustomerA-WiFi-5G", "security": "wpa3", "clients": 3, "enabled": True}],
            "clients": [{"mac": "aa", "hostname": "Laptop", "ip": "192.168.1.34", "band": "5GHz", "signal_dbm": -55}],
        }
        outcome = run_page(
            tmp_path,
            """
            await harness.open('WR3000 · AB-1');
            const overview = byId('p-overview').textContent;
            await harness.press(byId('t-devices'));
            const devices = byId('p-devices').textContent;
            await harness.press(byId('t-history'));
            const menu = ['d-tags', 'd-admin', 'd-remove'].map((id) => byId(id).hidden);
            return {overview, devices, more: byId('d-more-wrap').hidden, menu, sub: byId('d-sub').textContent,
                    paths: harness.paths()};
            """,
            setup=FLEET + f"harness.db.acsDetail[{json.dumps(ACS_ID)}] = {json.dumps(detail)};",
        )
        result = outcome["result"]
        overview = result["overview"]
        assert "wpa2 · 4 devices" in overview and "wpa3 · 3 devices" in overview
        assert "10.20.0.42" in overview and "6 days" in overview and "Every 5 min" in overview
        assert "Laptop" in result["devices"] and "5 GHz · strong signal" in result["devices"]
        assert result["more"] is False and result["menu"] == [False, True, True], (
            "Tags are GenieACS's; the admin password and Remove are for direct routers only")
        assert result["sub"] == "Cudy WR3000 · #1042 Customer A"
        assert f"GET {ACS_PATH}" in result["paths"]
        assert "GET /api/activity?router=acs%3A80AFCA-WR3000-AB%252D1&limit=50" in result["paths"]

    def test_an_uptime_without_seconds_falls_back_to_the_routers_own_text(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            return byId('p-overview').querySelectorAll('.facts div').map((d) => d.textContent);
            """,
            setup=NO_ACS
            + "harness.db.devices[0].status = {online: true, uptime_seconds: null, uptime_text: '3h 20m'};",
        )
        assert "Up for3h 20m" in outcome["result"]

    def test_no_left_out_part_shows_up_as_text(self, tmp_path: Path):
        many = [{"hostname": f"Device {n}", "ip": f"192.168.1.{n}"} for n in range(120)]
        outcome = run_page(
            tmp_path,
            """
            const seen = [];
            for (const name of harness.rows().map((row) => row[0].split('  ')[0])) {
              await harness.open(name);
              for (const tab of ['t-overview', 't-devices', 't-history']) {
                await harness.press(byId(tab));
                seen.push(name + ': ' + byId('drawer').textContent);
              }
            }
            for (const hash of ['#maintenance', '#activity', '#setup']) {
              await harness.go(hash);
              seen.push(document.body.textContent);
            }
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            seen.push(document.body.textContent);
            return seen.filter((text) => /\\b(null|undefined|NaN)\\b|\\[object/.test(text));
            """,
            setup=FLEET + f"""
            harness.handler = (req) => (req.path === '/api/devices/hk/clients'
              ? {reply({"clients": many})} : undefined);
            """,
        )
        assert outcome["result"] == []

    def test_escape_closes_the_panel_and_returns_focus_to_the_row(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            const inside = document.activeElement.id;
            harness.key('Escape');
            await harness.flush();
            return [inside, byId('drawer').hidden, document.activeElement.textContent];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == ["d-close", True, "Hennenman kantoor"]

    def test_actions_are_disabled_with_a_reason_when_a_router_cannot_take_them(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const state = () => ['d-wifi', 'd-refresh', 'd-reboot'].map((id) => [byId(id).disabled, byId(id).title]);
            await harness.open('Tower 3 office');
            const refused = [state(), byId('d-more-wrap').hidden];
            await harness.open('Tenda shop');
            const offline = state();
            await harness.open('WR1300 · CD1');
            const managedOffline = state();
            await harness.open('Hennenman kantoor');
            return {refused, offline, managedOffline, online: state()};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        states, more_hidden = result["refused"]
        assert all(disabled for disabled, _ in states)
        assert "refused SkyRouter's login" in states[0][1]
        assert more_hidden is False, "More holds the admin password, which is how a refused login is fixed"
        assert all(disabled and title == "The router is offline." for disabled, title in result["offline"])
        # GenieACS holds a change until a TR-069 router checks in, so being offline blocks nothing.
        assert result["managedOffline"] == [[False, ""], [False, ""], [False, ""]]
        assert result["online"] == [[False, ""], [False, ""], [False, ""]]

    def test_an_offline_managed_router_takes_changes_and_says_when_it_gets_them(self, tmp_path: Path):
        started = reply({"job": job("waiting_for_checkin", acs_id="80AFCA-WR1300-CD1")}, 202)
        pw = json.dumps("correct-horse-9")
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => (req.method === 'POST' ? {started} : undefined);
            await harness.open('WR1300 · CD1');
            await harness.press(byId('t-devices'));
            const devices = byId('p-devices').textContent;
            await harness.press(byId('d-wifi'));
            const wifi = [byId('wifi-note').hidden, byId('wifi-note').textContent];
            byId('w-pw1').value = {pw}; byId('w-pw2').value = {pw};
            await harness.press(byId('wifi-send'));
            await harness.press(byId('d-reboot'));
            const reboot = [byId('reboot-note').hidden, byId('reboot-note').textContent];
            await harness.press(byId('reboot-ok'));
            await harness.open('WR3000 · AB-1');
            await harness.press(byId('d-reboot'));
            const online = byId('reboot-note').hidden;
            await harness.press(byId('reboot-cancel'));
            const sent = harness.sent('POST', '/api/acs/devices/').map((r) => r.path);
            return {{devices, wifi, reboot, online, sent}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        note = "This router is offline. The change will be sent when it next checks in."
        assert result["wifi"] == [False, note] and result["reboot"] == [False, note]
        assert result["online"] is True, "a router that is online needs no such note"
        assert result["devices"] == "No device list until the router checks in."
        assert result["sent"] == [
            "/api/acs/devices/80AFCA-WR1300-CD1/wifi",
            "/api/acs/devices/80AFCA-WR1300-CD1/reboot",
        ]

    def test_a_managed_router_that_never_checked_in_says_so(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('WR1300 · CD1');
            const state = ['d-wifi', 'd-reboot'].map((id) => byId(id).disabled);
            await harness.press(byId('d-wifi'));
            return [state, byId('wifi-note').textContent];
            """,
            setup=FLEET + "harness.db.acsDevices[1].online = null;",
        )
        assert outcome["result"] == [
            [False, False], "This router has not checked in yet. The change will be sent when it does.",
        ]


# --- actions ------------------------------------------------------------------------------


@needs_node
class TestWifi:
    PASS = "correct-horse-9"
    FILL = f"byId('w-pw1').value = {json.dumps(PASS)}; byId('w-pw2').value = {json.dumps(PASS)};"

    def test_a_direct_change_sends_the_name_and_password_for_the_chosen_band(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-wifi'));
            await harness.press(byId('band-seg').querySelector('[data-band="5"]'));
            byId('w-ssid').value = 'Kantoor-5G';
            {self.FILL}
            await harness.press(byId('wifi-send'));
            return {{sent: harness.sent('POST', '/api/devices/hk/'), open: byId('wifi-dialog').open,
                     typed: byId('w-pw1').value, toasts: harness.toasts()}};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["sent"] == [
            sent("/api/devices/hk/ssid", {"ssid": "Kantoor-5G", "radio": "5G"}),
            sent("/api/devices/hk/wifi-password", {"password": self.PASS, "radio": "5G", "confirm": True}),
        ]
        assert result["open"] is False
        assert result["typed"] == "", "a typed Wi-Fi password must not linger in the closed dialog"
        assert result["toasts"][0] == {"kind": "applied", "title": "Applied",
                                       "text": "Hennenman kantoor accepted the change."}

    def test_both_bands_leaves_the_radio_out(self, tmp_path: Path):
        # No radio means both bands to CudyAdapter; it has no uci_section to fall back on.
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-wifi'));
            const checked = byId('band-seg').querySelector('[aria-checked=true]').dataset.band;
            byId('w-ssid').value = 'Shop';
            {self.FILL}
            await harness.press(byId('wifi-send'));
            return [checked, harness.sent('POST', '/api/devices/hk/').map((r) => r.body)];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == ["both", [{"ssid": "Shop"}, {"password": self.PASS, "confirm": True}]]

    @pytest.mark.parametrize(
        ("ssid", "first", "second", "expected"),
        [
            ("", "", "", "Enter a new Wi-Fi name, a new password, or both."),
            ("", "short", "short", "The password must be 8 to 63 characters."),
            ("", "pässword-1", "pässword-1", "Use letters, numbers and symbols only (no accents or emoji)."),
            ("", "correct-horse-9", "correct-horse-8", "The two passwords do not match. Nothing was changed."),
            ("ÅÅÅÅÅÅÅÅÅÅÅÅÅÅÅÅÅ", "", "", "The Wi-Fi name is too long (32 bytes at most)."),
        ],
    )
    def test_the_form_is_checked_before_anything_is_sent(self, tmp_path: Path, ssid, first, second, expected):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-wifi'));
            byId('w-ssid').value = {json.dumps(ssid)};
            byId('w-pw1').value = {json.dumps(first)};
            byId('w-pw2').value = {json.dumps(second)};
            await harness.press(byId('wifi-send'));
            const posts = harness.sent('POST', '/api/devices/').length;
            return [byId('wifi-error').textContent, byId('wifi-dialog').open, posts];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [expected, True, 0]

    def test_a_refusal_stays_in_the_open_dialog(self, tmp_path: Path):
        refusal = reply({"detail": "Smart Connect joins both bands into one network"}, 501)
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-wifi'));
            {self.FILL}
            await harness.press(byId('wifi-send'));
            return [byId('wifi-error').textContent, byId('wifi-dialog').open, byId('wifi-send').disabled];
            """,
            setup=NO_ACS + f"harness.handler = (req) => (req.path.endsWith('/wifi-password') ? {refusal} : undefined);",
        )
        assert outcome["result"] == ["Smart Connect joins both bands into one network", True, False]

    def test_a_tenda_names_one_radio_and_cannot_take_a_password(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.db.devices[2].status = {online: true};
            await loadRouters();
            await harness.open('Tenda shop');
            await harness.press(byId('d-wifi'));
            const seg = byId('band-seg');
            return {both: seg.querySelector('[data-band=both]').disabled,
                    checked: seg.querySelector('[aria-checked=true]').dataset.band,
                    password: byId('w-pw1').disabled, note: byId('wifi-note').textContent};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["both"] is True and result["checked"] == "5"
        assert result["password"] is True and "Tenda routers cannot change their Wi-Fi password" in result["note"]

    def test_a_tp_link_on_the_older_web_page_cannot_change_its_wifi(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.db.devices[1].status = {online: true};
            await loadRouters();
            await harness.open('Tower 3 office');
            return [byId('d-wifi').disabled, byId('d-wifi').title, byId('d-reboot').disabled];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [
            True,
            "TP-Link routers on this web page cannot change their Wi-Fi from here yet. Set the router up for an SSH"
            " login (transport: ssh in the router list) to change it here.",
            False,
        ]

    def test_an_ssh_router_keeps_its_configured_network_unless_a_band_is_picked(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-wifi'));
            const label = byId('band-seg').querySelector('[data-band=both]').textContent;
            byId('w-ssid').value = 'Lab';
            await harness.press(byId('wifi-send'));
            await harness.press(byId('d-wifi'));
            await harness.press(byId('band-seg').querySelector('[data-band="2.4"]'));
            byId('w-ssid').value = 'Lab-2G';
            await harness.press(byId('wifi-send'));
            return [label, harness.sent('POST', '/api/devices/hk/ssid').map((r) => r.body)];
            """,
            setup=NO_ACS + """
            Object.assign(harness.db.devices[0], {transport: 'ssh', metadata: {name: 'Hennenman kantoor',
              uci_section: 'default_radio0'}});
            """,
        )
        label, bodies = outcome["result"]
        assert label == "Its configured network"
        assert bodies == [{"ssid": "Lab"}, {"ssid": "Lab-2G", "radio": "2.4G"}]

    def test_a_managed_change_is_a_job_followed_to_its_end(self, tmp_path: Path):
        waiting = reply({"job": job("waiting_for_checkin", expected_by="2026-09-29T10:07:00+00:00")}, 202)
        done = reply({"job": job("acknowledged")})
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('WR3000 · AB-1');
            await harness.press(byId('d-wifi'));
            {self.FILL}
            harness.handler = (req) => (req.method === 'POST' ? {waiting} : undefined);
            await harness.press(byId('wifi-send'));
            const queued = harness.toasts()[0];
            const status = harness.row('WR3000 · AB-1').children[2].textContent;
            harness.handler = (req) => (req.path === '/api/acs/jobs/j1' ? {done} : undefined);
            await harness.advance(2000);
            return {{sent: harness.sent('POST', '{ACS_PATH}'), queued, status, applied: harness.toasts()[0],
                     after: harness.row('WR3000 · AB-1').children[2].textContent, open: byId('wifi-dialog').open}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["sent"] == [sent(f"{ACS_PATH}/wifi", {"band": "all", "passphrase": self.PASS})]
        assert result["open"] is False
        assert result["queued"] == {"kind": "queued", "title": "Queued",
                                    "text": "WR3000 · AB-1 picks this up at its next check-in, around 10:07."}
        assert result["status"] == "Change waiting"
        assert result["applied"] == {"kind": "applied", "title": "Applied",
                                     "text": "WR3000 · AB-1 accepted the change."}
        assert result["after"] == "Online"

    def test_a_refused_managed_change_says_so(self, tmp_path: Path):
        refused = reply({"job": job("rejected", message="The router refused the new Wi-Fi settings.")})
        outcome = run_page(
            tmp_path,
            f"""
            trackJob({json.dumps(job("waiting_for_checkin"))});
            harness.handler = (req) => (req.path === '/api/acs/jobs/j1' ? {refused} : undefined);
            await harness.advance(2000);
            const shown = harness.toasts()[0];
            await harness.advance(60000);
            return [shown, harness.toasts().length];
            """,
            setup=FLEET,
        )
        shown, remaining = outcome["result"]
        # GenieACS's own words, under the router's name.
        assert shown == {"kind": "refused", "title": "Refused",
                         "text": "WR3000 · AB-1: The router refused the new Wi-Fi settings."}
        assert remaining == 1, "a refusal stays until it is dismissed"

    def test_jobs_are_polled_every_2_s_then_every_15_s_after_three_minutes(self, tmp_path: Path):
        still = reply({"job": job("waiting_for_checkin")})
        outcome = run_page(
            tmp_path,
            f"""
            const polls = () => harness.requests.filter((r) => r.path === '/api/acs/jobs/j1').length;
            trackJob({json.dumps(job("waiting_for_checkin"))});
            harness.handler = (req) => (req.path === '/api/acs/jobs/j1' ? {still} : undefined);
            await harness.advance(10000);
            const early = polls();
            await harness.advance(170000);
            const threeMinutes = polls();
            await harness.advance(60000);
            return [early, threeMinutes, polls() - threeMinutes];
            """,
            setup=FLEET,
        )
        assert outcome["result"] == [5, 90, 4]

    @pytest.mark.parametrize("answer", ["ok", "cancel"])
    def test_an_inferred_band_is_confirmed_before_it_is_written(self, tmp_path: Path, answer):
        queued = reply({"job": job("queued")}, 202)
        inferred = reply({"detail": "The 5 GHz network was only inferred from its channel.", "plan": {"band": "5GHz"}},
                         409)
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('WR3000 · AB-1');
            await harness.press(byId('d-wifi'));
            await harness.press(byId('band-seg').querySelector('[data-band="5"]'));
            byId('w-ssid').value = 'Five';
            harness.handler = (req) => (req.method !== 'POST' ? undefined : req.body.confirm_guessed_band ? {queued}
                                        : {inferred});
            const sending = byId('wifi-send').click();
            await harness.flush();
            const asked = [byId('confirm-dialog').open, byId('confirm-text').textContent];
            await harness.press(byId('confirm-{answer}'));
            await sending;
            await harness.flush();
            return {{asked, bodies: harness.sent('POST', '{ACS_PATH}').map((r) => r.body),
                     error: byId('wifi-error').textContent, open: byId('wifi-dialog').open}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["asked"] == [True, "The 5 GHz network was only inferred from its channel."]
        first = {"band": "5GHz", "ssid": "Five"}
        if answer == "ok":
            assert result["bodies"] == [first, {**first, "confirm_guessed_band": True}]
            assert result["open"] is False
        else:
            assert result["bodies"] == [first]
            assert result["error"] == "Nothing was changed." and result["open"] is True

    def test_cancelling_a_job_asks_first(self, tmp_path: Path):
        cancelled = reply({"job": job("cancelled")})
        outcome = run_page(
            tmp_path,
            f"""
            trackJob({json.dumps(job("waiting_for_checkin"))});
            const cancel = () => harness.button(byId('toasts'), 'Cancel change');
            await harness.press(cancel());
            await harness.press(byId('confirm-cancel'));
            const kept = harness.sent('DELETE', '/api/acs/jobs/').length;
            harness.handler = (req) => (req.method === 'DELETE' ? {cancelled} : undefined);
            await harness.press(cancel());
            await harness.press(byId('confirm-ok'));
            return [kept, harness.sent('DELETE', '/api/acs/jobs/'), harness.toasts()[0]];
            """,
            setup=FLEET,
        )
        kept, deleted, ended = outcome["result"]
        assert kept == 0
        assert deleted == [sent("/api/acs/jobs/j1", None, kind=None)]
        assert ended["title"] == "Not applied" and ended["text"] == "Cancelled: nothing was changed on WR3000 · AB-1."


@needs_node
class TestRouterActions:
    def test_reboot_asks_first_then_calls_the_direct_route(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const reboots = () => harness.sent('POST', '/api/devices/hk/reboot');
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-reboot'));
            const asked = [byId('reboot-dialog').open, byId('reboot-sub').textContent];
            await harness.press(byId('reboot-cancel'));
            const cancelled = reboots().length;
            await harness.press(byId('d-reboot'));
            await harness.press(byId('reboot-ok'));
            const toast = harness.toasts()[0];
            // Esc keeps a dialog's last returnValue, which here was "reboot".
            await harness.press(byId('d-reboot'));
            harness.escape(byId('reboot-dialog'));
            await harness.flush();
            return {asked, cancelled, sent: reboots(), toast};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["asked"] == [True, "Hennenman kantoor"]
        assert result["cancelled"] == 0
        assert result["sent"] == [sent("/api/devices/hk/reboot", {"confirm": True})], "Esc must not reboot again"
        assert result["toast"]["title"] == "Reboot sent"

    def test_a_managed_reboot_and_refresh_are_jobs(self, tmp_path: Path):
        started = reply({"job": job("queued", kind="reboot")}, 202)
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => (req.method === 'POST' ? {started} : undefined);
            await harness.open('WR3000 · AB-1');
            await harness.press(byId('d-reboot'));
            await harness.press(byId('reboot-ok'));
            await harness.press(byId('d-refresh'));
            const asked = [byId('refresh-dialog').open, byId('refresh-scope').value];
            byId('refresh-scope').value = 'hosts';
            await harness.press(byId('refresh-send'));
            return {{asked, sent: harness.sent('POST', '{ACS_PATH}'), open: byId('refresh-dialog').open,
                     toast: harness.toasts()[0].title}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        # Reading everything is slow on some routers, so the Wi-Fi settings are offered first.
        assert result["asked"] == [True, "wifi"]
        assert result["sent"] == [
            sent(f"{ACS_PATH}/reboot", {"confirm": True}),
            sent(f"{ACS_PATH}/refresh", {"scope": "hosts"}),
        ]
        assert result["open"] is False and result["toast"] == "Reboot queued"

    def test_refreshing_a_direct_router_reads_its_status_again(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            const fresh = {online: true, firmware: '2.5.26', checked_at: new Date().toISOString()};
            harness.handler = (req) => (req.path === '/api/devices/hk/status'
              ? {status: 200, body: {device: 'hk', status: fresh}} : undefined);
            await harness.press(byId('d-refresh'));
            const reads = harness.paths().filter((p) => p.includes('/status'));
            return [reads, byId('p-overview').textContent.includes('2.5.26')];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [["GET /api/devices/hk/status"], True]

    def test_the_more_menu_sets_the_admin_password(self, tmp_path: Path):
        accepted = reply({"device": "t3", "verified": {"ok": True}})
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('Tower 3 office');
            await harness.press(byId('d-more'));
            const menu = [byId('d-menu').hidden, byId('d-more').getAttribute('aria-expanded')];
            await harness.press(byId('d-admin'));
            byId('pw-new').value = 's3cret-admin';
            byId('pw-confirm').value = 's3cret-admin';
            harness.handler = (req) => (req.path.endsWith('/password') ? {accepted} : undefined);
            await harness.press(byId('pw-save'));
            return {{menu, closed: byId('d-menu').hidden, sent: harness.sent('POST', '/api/devices/t3/password'),
                     open: byId('pw-dialog').open, typed: byId('pw-new').value, toast: harness.toasts()[0].title}};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["menu"] == [False, "true"] and result["closed"] is True
        assert result["sent"] == [sent("/api/devices/t3/password", {"password": "s3cret-admin", "verify": True})]
        assert result["open"] is False and result["typed"] == "" and result["toast"] == "Password saved"

    def test_the_password_dialog_is_locked_while_saving(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            showPassword(routerByKey('direct:hk'));
            byId('pw-new').value = 'new-admin-1'; byId('pw-confirm').value = 'new-admin-1';
            const gate = harness.deferred();
            harness.handler = (req) => (req.path.endsWith('/password') ? gate.promise : undefined);
            await harness.press(byId('pw-save'));
            harness.escape(byId('pw-dialog'));
            const during = [byId('pw-dialog').open, byId('pw-cancel').disabled, byId('pw-save').disabled];
            await harness.press(byId('pw-save'));
            gate.resolve({status: 200, body: {verified: null}});
            await harness.flush();
            const posts = harness.sent('POST', '/api/devices/hk/password').length;
            return [during, byId('pw-dialog').open, byId('pw-save').disabled, posts];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [[True, True, True], False, False, 1]

    def test_a_late_password_result_does_not_touch_another_routers_dialog(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const gate = harness.deferred();
            harness.handler = (req) => (req.path.endsWith('/password') ? gate.promise : undefined);
            showPassword(routerByKey('direct:hk'));
            byId('pw-new').value = 'n3w-admin'; byId('pw-confirm').value = 'n3w-admin';
            await harness.press(byId('pw-save'));
            // A browser may still force a busy dialog shut (a second Escape).
            byId('pw-dialog').close();
            showPassword(routerByKey('direct:t3'));
            byId('pw-new').value = 'typing';
            gate.resolve({status: 200, body: {verified: {ok: true}}});
            await harness.flush();
            return [byId('pw-dialog').open, byId('pw-sub').textContent, byId('pw-new').value, harness.toasts()[0].text];
            """,
            setup=NO_ACS,
        )
        still_open, sub, typed, text = outcome["result"]
        assert still_open is True, "the first router's answer closed the second one's dialog"
        assert sub.startswith("Tower 3 office") and typed == "typing"
        assert text == "Hennenman kantoor accepted the new password."

    def test_a_rejected_admin_password_is_reported_as_saved_but_refused(self, tmp_path: Path):
        rejected = reply({"verified": {"ok": False, "reason": "rejected", "error": "authentication failed"}})
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('Hennenman kantoor');
            showPassword(routerByKey('direct:hk'));
            byId('pw-new').value = 'typo'; byId('pw-confirm').value = 'typo';
            harness.handler = (req) => (req.path.endsWith('/password') ? {rejected} : undefined);
            await harness.press(byId('pw-save'));
            return harness.toasts()[0];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == {
            "kind": "refused", "title": "Saved, but not accepted",
            "text": "Saved, but Hennenman kantoor rejected the password: authentication failed",
        }

    def test_remove_asks_first_and_deletes_only_a_direct_router(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Tower 3 office');
            await harness.press(byId('d-more'));
            await harness.press(byId('d-remove'));
            const asked = byId('confirm-title').textContent;
            harness.db.devices = harness.db.devices.filter((d) => d.id !== 't3');
            await harness.press(byId('confirm-ok'));
            return {asked, sent: harness.sent('DELETE', '/api/devices/'), drawer: byId('drawer').hidden,
                    names: harness.rows().map((r) => r[0].split('  ')[0])};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["asked"] == "Remove Tower 3 office from SkyRouter?"
        assert result["sent"] == [sent("/api/devices/t3", None, kind=None)]
        assert result["drawer"] is True and "Tower 3 office" not in result["names"]

    def test_adopting_links_a_new_router_to_a_customer(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.press(byId('new-pill'));
            const list = byId('new-list');
            const labels = list.querySelectorAll('label span').map((s) => s.textContent);
            await harness.press(harness.button(list, 'Adopt'));
            const empty = harness.sent('POST', '/api/acs/devices/').length;
            list.querySelector('input').value = ' #1080 ';
            const limit = list.querySelector('input').getAttribute('maxlength');
            harness.db.acsNew = harness.db.acsNew.slice(1);
            // The toast names the customer as the server stored it.
            const adopted = {acs_id: '80AFCA-WR3000-NEW1', tags: [], customer: '#1080 Customer E'};
            harness.handler = (req) => (req.path.endsWith('/adopt') ? {status: 200, body: adopted} : undefined);
            await harness.press(harness.button(list, 'Adopt'));
            return {labels, empty, sent: harness.sent('POST', '/api/acs/devices/'), pill: byId('new-pill').textContent,
                    left: list.querySelectorAll('input').length, toast: harness.toasts()[0].text, limit};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["labels"] == ["WR3000 · serial NEW1", "M3000 · serial NEW2"]
        assert result["empty"] == 0, "a router is adopted only once it is linked to a customer"
        assert result["sent"] == [sent("/api/acs/devices/80AFCA-WR3000-NEW1/adopt", {"customer": "#1080"})]
        assert result["pill"] == "1 new router to adopt" and result["left"] == 1
        assert result["toast"] == "WR3000 · serial NEW1 is linked to #1080 Customer E."
        assert result["limit"] == "120", "the server takes a customer of up to 120 characters"


# --- session, header, theme ---------------------------------------------------------------


@needs_node
class TestSession:
    def test_a_stale_csrf_token_is_refreshed_once_and_the_request_retried(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.db.csrf = 't2';
            let first = true;
            harness.handler = (req) => {
              if (req.path !== '/logout' || !first) return undefined;
              first = false;
              return {status: 403, body: {detail: 'CSRF validation failed'}};
            };
            await harness.press(byId('signout'));
            return harness.sent('POST', '/logout').map((r) => r.csrf);
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == ["t1", "t2"]
        assert outcome["href"] == "/login"

    def test_a_failed_sign_out_does_not_pretend_to_succeed(self, tmp_path: Path):
        failure = reply({"detail": "internal server error"}, 500)
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => (req.path === '/logout' ? {failure} : undefined);
            await harness.press(byId('signout'));
            return harness.toasts()[0];
            """,
            setup=NO_ACS,
        )
        assert outcome["href"] == "http://skyrouter.test/"
        assert outcome["result"]["title"] == "Still signed in"

    def test_an_ended_session_goes_to_the_sign_in_page(self, tmp_path: Path):
        ended = reply({"detail": "authentication required"}, 401)
        outcome = run_page(
            tmp_path,
            "return harness.rows()[0][0];",
            setup=NO_ACS + f"harness.handler = (req) => (req.path.startsWith('/api/devices?') ? {ended} : undefined);",
        )
        assert outcome["href"] == "/login"

    def test_the_header_names_the_signed_in_person_and_marks_the_section(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const current = () => document.querySelectorAll('.nav a')
              .filter((a) => a.getAttribute('aria-current') === 'page').map((a) => a.dataset.view);
            const before = current();
            await harness.go('#activity');
            const shown = ['routers', 'maintenance', 'activity', 'setup'].filter((v) => !byId('view-' + v).hidden);
            return {name: byId('user-name').textContent, initial: byId('user-initial').textContent, before,
                    after: current(), shown};
            """,
            setup=NO_ACS + "harness.db.me = {actor: 'thandi M', mode: 'standalone'};",
        )
        assert outcome["result"] == {"name": "thandi M", "initial": "T", "before": ["routers"], "after": ["activity"],
                                     "shown": ["activity"]}

    def test_the_theme_toggle_switches_and_remembers(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const root = document.documentElement;
            const label = () => byId('theme-toggle').getAttribute('aria-label');
            await harness.press(byId('theme-toggle'));
            const dark = [root.dataset.theme, harness.storage.get('skybre-theme'), label()];
            await harness.press(byId('theme-toggle'));
            return [dark, root.dataset.theme, harness.storage.get('skybre-theme')];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [["dark", "dark", "Switch to light mode"], "light", "light"]

    def test_the_theme_still_switches_when_storage_is_blocked(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.press(byId('theme-toggle'));
            return document.documentElement.dataset.theme;
            """,
            setup=NO_ACS + "harness.storageBlocked = true; harness.dark = true;",
        )
        assert outcome["result"] == "light", "the system prefers dark, so the first switch is to light"

    def test_a_remembered_theme_applies_on_load(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            "return [document.documentElement.dataset.theme, byId('theme-toggle').getAttribute('aria-label')];",
            setup=NO_ACS + "harness.storage.set('skybre-theme', 'dark');",
        )
        assert outcome["result"] == ["dark", "Switch to light mode"]


# --- maintenance ---------------------------------------------------------------------------

ZONE = "Africa/Johannesburg"
PLAN = {
    "id": "a1b2c3d4e5f6", "name": "Weekly Sunday reboot", "enabled": True,
    "targets": {"all": True, "devices": [], "acs_devices": []},
    "schedule": {"days": ["sun"], "monthly_day": None, "start": "02:00", "duration_minutes": 120, "timezone": ZONE},
    "actions": ["firmware_check", "reboot"], "firmware": {},
    "guards": {"min_uptime_seconds": 3600, "skip_if_clients_over": None, "cooldown_hours": 20},
    "next_window": {"opens": "2026-10-04T00:00:00+00:00", "closes": "2026-10-04T02:00:00+00:00"},
    "window_open": False, "last_run": None,
}
LIBRARY = [
    {"name": "skybre-fw-0123456789abcdef0123456789abcdef", "filename": "wr3000.bin", "model_hint": "Cudy WR3000",
     "version": "2.4.2", "oui": "80AFCA", "product_class": "WR3000", "size": 14890000,
     "uploaded_at": "2026-09-27T11:20:00+00:00", "on_acs": True, "in_use_by": []},
]


@needs_node
class TestMaintenancePlans:
    def test_plans_are_shown_with_their_window_and_next_run(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            const card = byId('plans').querySelector('.plan');
            return [card.querySelector('h3').textContent, card.querySelector('dl').textContent,
                    byId('maint-next').textContent];
            """,
            setup=FLEET + f"harness.db.plans = [{json.dumps(PLAN)}];",
        )
        name, facts, upcoming = outcome["result"]
        assert name == "Weekly Sunday reboot"
        assert "RoutersAll routers (5)" in facts and "WindowSun 02:00–04:00" in facts
        assert "Check firmware" in facts and "Reboot" in facts
        assert "Next runSun 4 Oct 02:00" in facts, "the next window is shown in the plan's own timezone"
        assert upcoming == "Next run: Sun 4 Oct 02:00"

    def test_an_empty_or_unreadable_plan_list_says_so(self, tmp_path: Path):
        unreadable = reply({"detail": "plans are unreadable"}, 500)
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#maintenance');
            const empty = byId('plans').textContent;
            harness.handler = (req) => (req.path === '/api/maintenance/plans' ? {unreadable} : undefined);
            await loadPlans();
            return [empty, byId('plans').textContent];
            """,
            setup=NO_ACS,
        )
        empty, failed = outcome["result"]
        assert empty == "No maintenance plans yet. Create one to reboot or update routers on a schedule."
        assert "The plans could not be loaded: plans are unreadable" in failed

    @pytest.mark.parametrize(
        ("choice", "targets"),
        [("all", {"all": True}), ("direct", {"groups": ["direct"]}), ("managed", {"groups": ["managed"]}),
         ("cudy", {"groups": ["cudy"]})],
    )
    def test_a_new_plan_maps_the_dialog_to_the_plan_schema(self, tmp_path: Path, choice, targets):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#maintenance');
            await harness.press(byId('new-plan'));
            byId('p-name').value = 'Midweek check';
            await harness.press(byId('p-target').querySelector('[data-target={choice}]'));
            const days = byId('p-days');
            await harness.press(harness.button(days, 'Sun'));
            await harness.press(harness.button(days, 'Wed'));
            await harness.press(harness.button(days, 'Mon'));
            byId('p-start').value = '03:30';
            byId('p-duration').value = '180';
            await harness.press(byId('a-auto'));
            byId('g-uptime').value = '21600';
            byId('g-clients').value = '5';
            await harness.press(byId('plan-save'));
            return {{sent: harness.sent('POST', '/api/maintenance/plans'), open: byId('plan-dialog').open,
                     zone: byId('p-zone').textContent}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["sent"] == [sent("/api/maintenance/plans", {
            "name": "Midweek check", "targets": targets,
            "schedule": {"start": "03:30", "duration_minutes": 180, "timezone": ZONE, "days": ["mon", "wed"]},
            "actions": ["firmware_check", "auto_update_on", "reboot"],
            "guards": {"min_uptime_seconds": 21600, "skip_if_clients_over": 5},
        })]
        assert result["open"] is False and result["zone"] == f"Times are in {ZONE}."

    def test_the_plan_form_is_checked_before_saving(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('new-plan'));
            const save = async () => { await harness.press(byId('plan-save')); return byId('plan-error').textContent; };
            const errors = [await save()];
            byId('p-name').value = 'Nightly';
            byId('p-start').value = '25:00';
            errors.push(await save());
            byId('p-start').value = '01:00';
            await harness.press(byId('a-check')); await harness.press(byId('a-reboot'));
            errors.push(await save());
            await harness.press(byId('a-reboot'));
            byId('g-clients').value = 'lots';
            errors.push(await save());
            return [errors, harness.sent('POST', '/api/maintenance/plans').length];
            """,
            setup=NO_ACS,
        )
        errors, posts = outcome["result"]
        assert errors == [
            "Give the plan a name.",
            "Enter the start time as HH:MM, e.g. 02:00.",
            "Choose at least one thing for the plan to do.",
            "The device limit must be a whole number, or empty for no limit.",
        ]
        assert posts == 0

    def test_installing_from_the_library_names_the_newest_file_per_product_class(self, tmp_path: Path):
        older = {**LIBRARY[0], "name": "skybre-fw-ffffffffffffffffffffffffffffffff", "version": "2.4.1"}
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('new-plan'));
            byId('p-name').value = 'Firmware';
            await harness.press(byId('p-target').querySelector('[data-target=managed]'));
            await harness.press(byId('a-install'));
            await harness.press(byId('plan-save'));
            return harness.sent('POST', '/api/maintenance/plans').map((r) => [r.body.actions, r.body.firmware]);
            """,
            setup=FLEET + f"harness.db.library = {json.dumps([LIBRARY[0], older])};",
        )
        actions = ["firmware_check", "firmware_update", "reboot"]
        assert outcome["result"] == [[actions, {"WR3000": LIBRARY[0]["name"]}]]

    def test_install_needs_a_library_file_and_cannot_target_direct_routers(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('new-plan'));
            byId('p-name').value = 'Firmware';
            await harness.press(byId('a-install'));
            await harness.press(byId('plan-save'));
            const empty = byId('plan-error').textContent;
            await harness.press(byId('p-target').querySelector('[data-target=direct]'));
            const posts = harness.sent('POST', '/api/maintenance/plans').length;
            return [empty, byId('a-install').disabled, byId('a-install').checked, posts];
            """,
            setup=FLEET,
        )
        empty, disabled, checked, posts = outcome["result"]
        assert empty.startswith("The firmware library is empty.")
        assert disabled is True and checked is False and posts == 0

    def test_edit_switch_run_and_delete(self, tmp_path: Path):
        results = [{"status": "done"}, {"status": "done"}, {"status": "queued"}, {"status": "skipped"}]
        ran = reply({"plan": PLAN["id"], "results": results})
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            const card = () => byId('plans').querySelector('.plan');
            await harness.press(harness.button(card(), 'Edit'));
            const prefilled = [byId('p-name').value, byId('p-start').value,
                               byId('p-days').querySelector('[aria-pressed=true]').textContent,
                               byId('plan-title').textContent, byId('plan-delete').hidden];
            byId('p-name').value = 'Sunday reboot';
            await harness.press(byId('plan-save'));
            await harness.press(card().querySelector('input[type=checkbox]'));
            await harness.press(harness.button(card(), 'Run now'));
            await harness.press(byId('confirm-ok'));
            const runToast = harness.toasts()[0];
            await harness.press(harness.button(card(), 'Edit'));
            await harness.press(byId('plan-delete'));
            await harness.press(byId('confirm-ok'));
            return {prefilled, put: harness.sent('PUT', '/api/maintenance/plans/'),
                    run: harness.sent('POST', '/api/maintenance/plans/'),
                    deleted: harness.sent('DELETE', '/api/maintenance/plans/'), runToast};
            """,
            setup=FLEET + f"""
            harness.db.plans = [{json.dumps(PLAN)}];
            harness.handler = (req) => (req.path.endsWith('/run') ? {ran} : undefined);
            """,
        )
        result = outcome["result"]
        assert result["prefilled"] == ["Weekly Sunday reboot", "02:00", "Sun", "Edit maintenance plan", False]
        path = f"/api/maintenance/plans/{PLAN['id']}"
        edited, switched = result["put"]
        assert edited == sent(path, {
            "name": "Sunday reboot", "targets": {"all": True},
            "schedule": {"start": "02:00", "duration_minutes": 120, "timezone": ZONE, "days": ["sun"]},
            "actions": ["firmware_check", "reboot"],
            "guards": {"min_uptime_seconds": 3600, "skip_if_clients_over": None, "cooldown_hours": 20},
        })
        assert switched["body"] == {"enabled": False}
        assert result["run"] == [sent(f"{path}/run", {"confirm": True})]
        assert result["runToast"]["text"] == (
            '"Weekly Sunday reboot": 2 done, 1 waiting for check-in, 1 skipped. Details are in Activity.'
        )
        assert result["deleted"] == [sent(path, None, kind=None)]

    def test_a_switched_off_plan_says_so_in_words(self, tmp_path: Path):
        off = {**PLAN, "id": "b1b2c3d4e5f6", "name": "Monthly firmware", "enabled": False, "next_window": None}
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            const cards = byId('plans').querySelectorAll('.plan');
            return cards.map((c) => [c.className, c.querySelector('.plan-head').textContent]);
            """,
            setup=NO_ACS + f"harness.db.plans = [{json.dumps(PLAN)}, {json.dumps(off)}];",
        )
        assert outcome["result"] == [["plan", "Weekly Sunday reboot"], ["plan off", "Monthly firmwareOff"]]

    def test_a_plan_naming_routers_one_by_one_keeps_them(self, tmp_path: Path):
        custom = {**PLAN, "targets": {"all": False, "devices": ["hk"], "acs_devices": []}}
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(harness.button(byId('plans').querySelector('.plan'), 'Edit'));
            const hint = byId('p-target-count').textContent;
            await harness.press(byId('plan-save'));
            return [hint, harness.sent('PUT', '/api/maintenance/plans/')[0].body.targets];
            """,
            setup=NO_ACS + f"harness.db.plans = [{json.dumps(custom)}];",
        )
        hint, targets = outcome["result"]
        assert hint.startswith("This plan names 1 router one by one")
        assert targets == {"all": False, "devices": ["hk"], "acs_devices": []}


@needs_node
class TestMaintenanceFirmware:
    FIRMWARE = {"version": "2.5.25", "hardware": "AP1300 V1.1",
                "auto_update": {"enabled": True, "window_start_hour": 3, "window": "03:00-05:00"}}

    def firmware_setup(self) -> str:
        return FLEET + f"""
        harness.db.library = {json.dumps(LIBRARY)};
        const firmware = {reply({"firmware": self.FIRMWARE})};
        harness.handler = (req) => (req.path === '/api/devices/hk/firmware' ? firmware : undefined);
        """

    def test_each_router_shows_its_firmware_and_window(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            return harness.rows('fw-rows');
            """,
            setup=self.firmware_setup(),
        )
        rows = {row[0]: row for row in outcome["result"]}
        assert rows["Hennenman kantoorAP1300 V1.1"][1:3] == ["2.5.25Not checked yet", "On · 03:00-05:00"]
        assert rows["WR3000 · AB-1WR3000"][1:3] == ["2.3.82.4.2 is in the library", "From the library (TR-069)"]
        assert rows["Tower 3 officeTL-WR840N"][1] == "—Login refused", "a router refusing the login is not asked"

    def test_changing_the_window_turns_automatic_updates_on_or_off(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            const row = () => byId('fw-rows').children.find((tr) => tr.dataset.key === 'direct:hk');
            await harness.press(harness.button(row(), 'Change window'));
            const prefilled = [byId('auto-on').checked, byId('auto-window').value];
            byId('auto-window').value = '1';
            await harness.press(byId('auto-save'));
            const moved = row().children[2].textContent;
            await harness.press(harness.button(row(), 'Change window'));
            await harness.press(byId('auto-on'));
            const windowOff = byId('auto-window').disabled;
            await harness.press(byId('auto-save'));
            const sent = harness.sent('PUT', '/api/devices/hk/firmware/auto-update').map((r) => [r.body, r.csrf]);
            return {prefilled, moved, windowOff, sent};
            """,
            setup=self.firmware_setup(),
        )
        result = outcome["result"]
        assert result["prefilled"] == [True, "3"]
        assert result["moved"] == "On · 01:00–03:00"
        assert result["windowOff"] is True
        assert result["sent"] == [[{"enabled": True, "window_start_hour": 1}, "t1"], [{"enabled": False}, "t1"]]

    def test_a_late_window_result_does_not_close_another_routers_dialog(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const gate = harness.deferred();
            harness.handler = (req) => (req.method === 'PUT' ? gate.promise : undefined);
            openAuto(routerByKey('direct:hk'));
            await harness.press(byId('auto-save'));
            byId('auto-dialog').close();
            openAuto(routerByKey('direct:td'));
            gate.resolve({status: 200, body: {window: '03:00-05:00'}});
            await harness.flush();
            return [byId('auto-dialog').open, byId('auto-sub').textContent];
            """,
            setup=NO_ACS,
        )
        still_open, sub = outcome["result"]
        assert still_open is True and sub.startswith("Tenda shop")

    def test_check_now_shows_progress_and_blocks_a_second_click(self, tmp_path: Path):
        found = reply({"check": {"available": True, "current": "2.5.25", "latest": "2.5.26", "note": ""},
                       "installed": False})
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            const gate = harness.deferred();
            const base = harness.handler;
            harness.handler = (req) => (req.path === '/api/devices/hk/firmware/check' ? gate.promise : base(req));
            const row = () => byId('fw-rows').children.find((tr) => tr.dataset.key === 'direct:hk');
            await harness.press(harness.button(row(), 'Check now'));
            const busy = harness.button(row(), 'Checking…');
            const during = [busy.getAttribute('aria-disabled'), row().children[1].textContent,
                            harness.toasts()[0].title, document.activeElement === busy];
            await busy.click();
            gate.resolve({found});
            await harness.flush();
            return {{during, after: row().children[1].textContent, button: harness.button(row(), 'Check now').disabled,
                     focused: document.activeElement.textContent,
                     sent: harness.sent('POST', '/api/devices/hk/firmware/check'), toast: harness.toasts()[0].text}};
            """,
            setup=self.firmware_setup(),
        )
        result = outcome["result"]
        # Busy rather than disabled, so the button keeps keyboard focus through the check.
        assert result["during"] == ["true", "2.5.25Asking the router… this can take up to a minute", "Checking…", True]
        assert result["sent"] == [sent("/api/devices/hk/firmware/check", {})]
        assert result["after"] == "2.5.252.5.26 available" and result["button"] is False
        assert result["focused"] == "Check now"
        assert result["toast"] == "2.5.26 is available for Hennenman kantoor."

    def test_installing_a_library_file_on_a_managed_router(self, tmp_path: Path):
        queued = reply({"job": job("queued", kind="firmware")}, 202)
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            const row = byId('fw-rows').children.find((tr) => tr.dataset.key === 'acs:{ACS_ID}');
            harness.handler = (req) => (req.method === 'POST' ? {queued} : undefined);
            await harness.press(harness.button(row, 'Install 2.4.2'));
            const asked = byId('confirm-title').textContent;
            await harness.press(byId('confirm-ok'));
            return {{asked, sent: harness.sent('POST', '{ACS_PATH}'), toast: harness.toasts()[0]}};
            """,
            setup=self.firmware_setup(),
        )
        result = outcome["result"]
        assert result["asked"] == "Install firmware 2.4.2 on WR3000 · AB-1?"
        assert result["sent"] == [sent(f"{ACS_PATH}/firmware", {"firmware": LIBRARY[0]["name"], "confirm": True})]
        assert result["toast"]["title"] == "Firmware queued"

    def test_uploading_and_removing_library_files(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            const first = [byId('fw-model').value, byId('fw-oui').value, byId('fw-class').value];
            await harness.choose(byId('fw-model'), '80AFCA|WR3000');
            const prefilled = [first, byId('fw-oui').value, byId('fw-class').value];
            await harness.press(byId('fw-upload'));
            const missing = byId('fw-error').textContent;
            byId('fw-file').files = [{name: 'wr3000 v2.4.3.bin', size: 15000000}];
            byId('fw-version').value = '2.4.3';
            await harness.press(byId('fw-upload'));
            await harness.press(harness.button(byId('fw-library'), 'Remove'));
            await harness.press(byId('confirm-ok'));
            return {prefilled, missing, upload: harness.sent('POST', '/api/acs/firmware'),
                    removed: harness.sent('DELETE', '/api/acs/firmware/')};
            """,
            setup=self.firmware_setup(),
        )
        result = outcome["result"]
        # The known TR-069 models fill in the OUI and product class, which are easy to mistype.
        assert result["prefilled"] == [["80AFCA|WR1300", "80AFCA", "WR1300"], "80AFCA", "WR3000"]
        assert result["missing"] == "Choose the firmware file."
        query = "version=2.4.3&oui=80AFCA&product_class=WR3000&filename=wr3000+v2.4.3.bin&model_hint=Cudy+WR3000"
        assert result["upload"] == [sent(f"/api/acs/firmware?{query}", {"file": "wr3000 v2.4.3.bin", "size": 15000000},
                                         kind="application/octet-stream")]
        assert result["removed"] == [sent(f"/api/acs/firmware/{LIBRARY[0]['name']}", None, kind=None)]


# --- activity ------------------------------------------------------------------------------

ENTRIES = [
    {"id": "e2", "at": "2026-09-28T14:04:00+00:00", "who": "Skybre staff", "router": "hk", "router_name": "hk",
     "kind": "wifi", "what": "Wi-Fi password changed (2.4G, 5G)", "result": "applied", "details": {}},
    {"id": "e1", "at": "2026-09-28T02:04:00+00:00", "who": "Maintenance: Weekly Sunday reboot", "router": "acs:gone",
     "router_name": "Old router", "kind": "maintenance", "what": "Rebooted", "result": "queued", "details": {}},
]


@needs_node
class TestActivity:
    def test_filters_load_more_and_the_export_link(self, tmp_path: Path):
        older = reply({"entries": [{**ENTRIES[1], "id": "e0"}], "next_before": None})
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#activity');
            const first = [harness.rows('activity-rows'), byId('activity-count').textContent,
                           byId('activity-more-row').hidden];
            await harness.press(byId('activity-more'));
            const more = harness.rows('activity-rows').length;
            await harness.choose(byId('f-type'), 'wifi');
            await harness.choose(byId('f-router'), 'hk');
            await harness.choose(byId('f-who'), 'Skybre staff');
            return {first, more, href: byId('export').getAttribute('href'),
                    people: byId('f-who').options.map((o) => o.textContent),
                    reads: harness.paths().filter((p) => p.startsWith('GET /api/activity'))};
            """,
            setup=NO_ACS + f"""
            harness.db.activity = {json.dumps(ENTRIES)};
            harness.db.nextBefore = 'e1';
            harness.handler = (req) => (req.path.includes('before=e1') ? {older} : undefined);
            """,
        )
        result = outcome["result"]
        rows, count, more_hidden = result["first"]
        assert rows == [
            ["28 Sep 14:04", "Skybre staff", "Hennenman kantoor", "Wi-Fi password changed (2.4G, 5G)", "Applied"],
            ["28 Sep 02:04", "Maintenance: Weekly Sunday reboot", "Old router", "Rebooted", "Waiting for check-in"],
        ]
        assert count == "2 changes, more available" and more_hidden is False
        assert result["more"] == 3
        assert result["href"] == "/api/activity.csv?router=hk&who=Skybre+staff&kind=wifi"
        assert result["people"] == ["Everyone", "Maintenance: Weekly Sunday reboot", "Skybre staff"]
        assert result["reads"] == [
            "GET /api/activity?limit=100",
            "GET /api/activity?limit=100&before=e1",
            "GET /api/activity?kind=wifi&limit=100",
            "GET /api/activity?router=hk&kind=wifi&limit=100",
            "GET /api/activity?router=hk&who=Skybre+staff&kind=wifi&limit=100",
        ]

    def test_an_activity_row_opens_the_routers_history(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#activity');
            await harness.press(byId('activity-rows').children[0]);
            return [location.hash, byId('drawer').hidden, byId('t-history').getAttribute('aria-selected'),
                    byId('d-name').textContent];
            """,
            setup=NO_ACS + f"harness.db.activity = {json.dumps(ENTRIES)};",
        )
        assert outcome["result"] == ["#routers", False, "true", "Hennenman kantoor"]

    def test_empty_and_failed_history(self, tmp_path: Path):
        refused = reply({"detail": "before must be an activity entry id"}, 400)
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#activity');
            const empty = harness.rows('activity-rows')[0][0];
            harness.handler = (req) => (req.path.startsWith('/api/activity') ? {refused} : undefined);
            await harness.choose(byId('f-type'), 'reboot');
            return [empty, byId('activity-rows').textContent];
            """,
            setup=NO_ACS,
        )
        empty, failed = outcome["result"]
        assert empty == "No changes match these filters."
        assert "The history could not be loaded: before must be an activity entry id" in failed


# --- setup ---------------------------------------------------------------------------------

WIFI_PASS = "sunflower-garden-7"
FILL_SETUP = f"""
byId('s-customer').value = '#1080 Customer E';
byId('s-name').value = 'Customer 1080 home';
byId('s-ip').value = '10.20.0.15';
byId('s-ssid24').value = 'CustomerE';
byId('s-wifipass').value = {json.dumps(WIFI_PASS)};
"""


@needs_node
class TestSetup:
    def test_saving_is_blocked_until_remote_management_is_ticked(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            {FILL_SETUP}
            await harness.press(byId('setup-save'));
            const blocked = [byId('setup-error').textContent, document.activeElement.id];
            const before = harness.sent('POST', '/api/setup/records').length;
            await harness.press(byId('c-remote'));
            await harness.press(byId('c-acs'));
            await harness.press(byId('setup-save'));
            await harness.advance(0);
            return {{blocked, before, sent: harness.sent('POST', '/api/setup/records'), toast: harness.toasts()[0],
                     cleared: byId('s-wifipass').value, count: byId('check-count').textContent}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["blocked"][0].startswith('Tick "Remote web management is on" first.')
        assert result["blocked"][1] == "c-remote" and result["before"] == 0
        assert result["sent"] == [sent("/api/setup/records", {
            "customer": "#1080 Customer E", "model": "Cudy WR3000", "ip": "10.20.0.15", "method": "managed",
            "ssid_24": "CustomerE", "wifi_password": WIFI_PASS, "name": "Customer 1080 home",
            "checklist": {"remote_management": True, "acs_configured": True, "default_password_changed": False,
                          "firmware_updated": False},
        })]
        assert result["toast"]["text"] == "Customer 1080 home is on record and appears once it checks in."
        # The checklist sits outside the form, and the next router must be ticked off afresh.
        assert result["cleared"] == "" and result["count"] == "0 of 4 done"

    def test_a_router_skybre_logs_in_to_carries_its_admin_login(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            {FILL_SETUP}
            byId('s-ssid5').value = 'CustomerE-5G';
            byId('s-notes').value = 'lounge';
            await harness.choose(byId('s-model'), 'TP-Link Archer C64');
            await harness.press(byId('setup-save'));
            const needsPassword = byId('setup-error').textContent;
            byId('s-admin-pass').value = 'router-admin-1';
            await harness.press(byId('c-remote'));
            await harness.press(byId('c-default'));
            await harness.press(byId('setup-save'));
            return {{needsPassword, help: byId('c-remote-help').textContent,
                     sent: harness.sent('POST', '/api/setup/records').map((r) => r.body)}};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["needsPassword"] == "Enter the router admin password so Skybre can sign in to it."
        assert result["help"].startswith("TP-Link:")
        assert result["sent"] == [{
            "customer": "#1080 Customer E", "model": "TP-Link Archer C64", "ip": "10.20.0.15", "method": "direct",
            "ssid_24": "CustomerE", "wifi_password": WIFI_PASS, "name": "Customer 1080 home", "ssid_5": "CustomerE-5G",
            "notes": "lounge", "admin_username": "admin", "admin_password": "router-admin-1",
            "checklist": {"remote_management": True, "acs_configured": False, "default_password_changed": True,
                          "firmware_updated": False},
        }]

    def test_the_model_list_is_the_servers(self, tmp_path: Path):
        models = ["Cudy WR3000", "Cudy X6", "Other"]
        listing = reply({"records": [], "models": models})
        outcome = run_page(
            tmp_path,
            f"""
            const before = byId('s-model').options.map((o) => o.value);
            byId('s-model').value = 'Other';
            await harness.go('#setup');
            const after = [byId('s-model').options.map((o) => o.value), byId('s-model').value];
            await harness.choose(byId('s-model'), 'Cudy X6');
            {FILL_SETUP}
            byId('s-admin-pass').value = 'router-admin-1';
            await harness.press(byId('c-remote'));
            await harness.press(byId('setup-save'));
            return {{before, after, help: byId('c-remote-help').textContent,
                     sent: harness.sent('POST', '/api/setup/records').map((r) => r.body.model)}};
            """,
            setup=FLEET + f"harness.handler = (req) => (req.method === 'GET' && req.path === '/api/setup/records'"
            f" ? {listing} : undefined);",
        )
        result = outcome["result"]
        assert "Cudy X6" not in result["before"], "the page's own copy shows until the server's list arrives"
        # The choice made before the list arrived is kept, since the server still offers it.
        assert result["after"] == [models, "Other"]
        assert result["help"].startswith("Cudy:") and result["sent"] == ["Cudy X6"]

    def test_without_tr069_only_makes_skybre_can_sign_in_to_are_offered(self, tmp_path: Path):
        # The server refuses "Other" for a router Skybre logs in to, and says to pick TR-069, which is off.
        models = ["Cudy WR3000", "Cudy X6", "Other"]
        listing = reply({"records": [], "models": models})
        scenario = """
            const before = byId('s-model').options.map((o) => o.value);
            await harness.go('#setup');
            return [before, byId('s-model').options.map((o) => o.value)];
            """
        handler = (f"harness.handler = (req) => (req.method === 'GET' && req.path === '/api/setup/records'"
                   f" ? {listing} : undefined);")
        off = run_page(tmp_path, scenario, setup=NO_ACS + handler)["result"]
        on = run_page(tmp_path, scenario, setup=FLEET + handler)["result"]
        assert "Other" not in off[0] and off[1] == ["Cudy WR3000", "Cudy X6"]
        assert "Other" in on[0] and on[1] == models

    def test_the_acs_address_is_the_servers_setting(self, tmp_path: Path):
        scenario = """
            await harness.go('#setup');
            await harness.press(byId('copy-acs'));
            return [byId('acs-url').textContent, byId('copy-acs').disabled, harness.clipboard];
            """
        configured = run_page(tmp_path, scenario, setup=FLEET + "harness.db.acs.cwmp_url = 'http://10.10.0.2:7547/';")
        assert configured["result"] == ["http://10.10.0.2:7547/", False, "http://10.10.0.2:7547/"]
        unset = run_page(tmp_path, scenario, setup=FLEET)
        assert unset["result"] == ["Not set on this server (ROUTER_MANAGER_ACS_CWMP_URL)", True, None]

    def test_a_hostname_is_left_to_the_server_but_an_empty_address_is_caught(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            {FILL_SETUP}
            byId('s-admin-pass').value = 'router-admin-1';
            await harness.press(byId('c-remote'));
            byId('s-ip').value = '  ';
            await harness.press(byId('setup-save'));
            const empty = byId('setup-error').textContent;
            byId('s-wifipass').value = '';
            byId('s-ip').value = 'router-1080.skybre.lan';
            await harness.press(byId('setup-save'));
            const noPassword = byId('setup-error').textContent;
            byId('s-wifipass').value = {json.dumps(WIFI_PASS)};
            await harness.press(byId('setup-save'));
            return {{empty, noPassword, sent: harness.sent('POST', '/api/setup/records').map((r) => r.body.ip)}};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["empty"] == "Enter the router IP address, e.g. 10.20.0.15."
        assert result["noPassword"] == "Enter the Wi-Fi password."
        assert result["sent"] == ["router-1080.skybre.lan"]

    def test_a_server_refusal_is_shown_and_nothing_is_cleared(self, tmp_path: Path):
        refusal = reply({"detail": "remote_management must be confirmed"}, 400)
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            {FILL_SETUP}
            byId('s-admin-pass').value = 'router-admin-1';
            await harness.press(byId('c-remote'));
            harness.handler = (req) => (req.method === 'POST' ? {refusal} : undefined);
            await harness.press(byId('setup-save'));
            return [byId('setup-error').textContent, byId('s-customer').value, byId('setup-save').disabled];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == ["remote_management must be confirmed", "#1080 Customer E", False]

    @pytest.mark.parametrize("answer", ["ok", "cancel"])
    def test_a_public_address_asks_before_its_password_would_cross_the_internet(self, tmp_path: Path, answer):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            {FILL_SETUP}
            byId('s-ip').value = '203.0.113.9';
            byId('s-admin-pass').value = 'router-admin-1';
            await harness.press(byId('c-remote'));
            await harness.press(byId('setup-save'));
            const asked = [byId('confirm-dialog').open, harness.sent('POST', '/api/setup/records').length];
            await harness.press(byId('confirm-{answer}'));
            byId('s-ip').value = '10.8.0.2';
            return [asked, harness.sent('POST', '/api/setup/records').map((r) => r.body.ip)];
            """,
            setup=NO_ACS,
        )
        asked, ips = outcome["result"]
        assert asked == [True, 0], "nothing may be sent before the operator answers"
        assert ips == (["203.0.113.9"] if answer == "ok" else [])

    def test_a_private_address_is_saved_without_asking(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            {FILL_SETUP}
            byId('s-ip').value = '100.64.0.9';
            byId('s-admin-pass').value = 'router-admin-1';
            await harness.press(byId('c-remote'));
            await harness.press(byId('setup-save'));
            return [byId('confirm-dialog').open, harness.sent('POST', '/api/setup/records').length];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [False, 1]

    def test_a_saved_password_is_revealed_on_request_and_masked_again(self, tmp_path: Path):
        record = {"id": "rec1", "customer": "#1057 Customer B", "model": "Cudy M3000 mesh", "ip": "10.20.0.57",
                  "method": "managed", "ssid_24": "CustomerB-Home", "created_at": "2026-09-27T16:40:00+00:00",
                  "checklist": {"remote_management": True}, "checklist_complete": True, "password_saved": True}
        lost = {**record, "id": "rec0", "customer": "#1001 Customer Z", "checklist_complete": False,
                "password_saved": False}
        revealed = reply({"wifi_password": WIFI_PASS})
        outcome = run_page(
            tmp_path,
            f"""
            await harness.go('#setup');
            const root = byId('records');
            const listed = root.textContent;
            const lostButton = root.children[1].querySelector('button');
            const lost = [root.children[1].textContent.includes('checklist incomplete'), lostButton.disabled];
            await harness.press(harness.button(root, 'Show password'));
            const shown = [root.querySelector('.secret').textContent, harness.buttons(root.children[0])];
            await harness.press(harness.button(root, 'Hide'));
            return {{listed, lost, shown, hidden: root.querySelector('.secret').textContent,
                     anywhere: document.body.textContent.includes({json.dumps(WIFI_PASS)}),
                     sent: harness.sent('POST', '/api/setup/records/')}};
            """,
            setup=FLEET + f"""
            harness.db.records = [{json.dumps(record)}, {json.dumps(lost)}];
            harness.handler = (req) => (req.path.endsWith('/reveal') ? {revealed} : undefined);
            """,
        )
        result = outcome["result"]
        assert "#1057 Customer B" in result["listed"] and "TR-069 · checklist complete" in result["listed"]
        assert result["lost"] == [True, True], "a record whose password is gone offers nothing to reveal"
        assert WIFI_PASS not in result["listed"], "the list itself never carries the password"
        assert result["shown"] == [WIFI_PASS, ["Hide"]]
        assert result["hidden"] == "••••••••••" and result["anywhere"] is False
        assert result["sent"] == [sent("/api/setup/records/rec1/reveal", {"confirm": True})]


# --- keyboard focus and live regions --------------------------------------------------------


@needs_node
class TestFocusSurvivesRedraws:
    FIRMWARE = reply({"firmware": TestSidePanel.FIRMWARE})

    def test_a_job_poll_that_changes_nothing_leaves_the_toast_alone(self, tmp_path: Path):
        # The toast is in an aria-live region: rewriting it re-reads it, and replacing its button drops focus.
        still = reply({"job": job("waiting_for_checkin")})
        done = reply({"job": job("acknowledged")})
        outcome = run_page(
            tmp_path,
            f"""
            trackJob({json.dumps(job("waiting_for_checkin"))});
            const toastNode = byId('toasts').children[0];
            const cancel = harness.button(byId('toasts'), 'Cancel change');
            cancel.focus();
            let writes = 0;
            for (const part of toastNode.querySelectorAll('span, p')) {{
              const own = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(part), 'textContent');
              Object.defineProperty(part, 'textContent', {{
                get() {{ return own.get.call(this); }}, set(value) {{ writes++; own.set.call(this, value); }},
              }});
            }}
            harness.handler = (req) => (req.path === '/api/acs/jobs/j1' ? {still} : undefined);
            await harness.advance(6000);
            const polled = harness.requests.filter((r) => r.path === '/api/acs/jobs/j1').length;
            const kept = [harness.button(byId('toasts'), 'Cancel change') === cancel,
                          document.activeElement === cancel, writes];
            harness.handler = (req) => (req.path === '/api/acs/jobs/j1' ? {done} : undefined);
            await harness.advance(2000);
            return {{polled, kept, after: harness.buttons(byId('toasts')), toast: harness.toasts()[0]}};
            """,
            setup=FLEET,
        )
        result = outcome["result"]
        assert result["polled"] == 3
        assert result["kept"] == [True, True, 0]
        assert result["after"] == ["×"] and result["toast"]["title"] == "Applied"

    def test_a_status_chip_keeps_focus_once_pressed(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const chip = (id) => byId('status-chips').querySelector(`[data-status=${id}]`);
            const online = chip('online');
            await harness.press(online);
            const focused = document.activeElement;
            return [focused === online, focused.getAttribute('aria-pressed'), chip('all').getAttribute('aria-pressed'),
                    harness.rows().length];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [True, "true", "false", 1]

    def test_a_day_in_the_plan_dialog_keeps_focus_once_pressed(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('new-plan'));
            await harness.press(harness.button(byId('p-days'), 'Mon'));
            const focused = document.activeElement;
            return [focused.textContent, focused.getAttribute('aria-pressed'), byId('p-days').contains(focused)];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == ["Mon", "true", True]

    def test_a_plans_switch_run_now_and_edit_keep_focus_once_their_request_ends(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            const card = () => byId('plans').querySelector('.plan');
            const where = () => {
              const node = document.activeElement;
              return [node.tagName, node.textContent || node.getAttribute('aria-label'), card().contains(node)];
            };
            await harness.press(card().querySelector('input[type=checkbox]'));
            const switched = where();
            await harness.press(harness.button(card(), 'Run now'));
            await harness.press(byId('confirm-ok'));
            const ran = where();
            await harness.press(harness.button(card(), 'Edit'));
            await harness.press(byId('plan-save'));
            return {switched, ran, edited: where()};
            """,
            setup=FLEET + f"harness.db.plans = [{json.dumps(PLAN)}];",
        )
        result = outcome["result"]
        assert result["switched"] == ["INPUT", "Plan Weekly Sunday reboot switched on", True]
        assert result["ran"] == ["BUTTON", "Run now", True]
        assert result["edited"] == ["BUTTON", "Edit", True]

    def test_check_for_updates_keeps_focus_while_it_runs_and_after(self, tmp_path: Path):
        found = reply({"check": {"available": False}})
        outcome = run_page(
            tmp_path,
            f"""
            harness.gate = harness.deferred();
            harness.handler = (req) => (req.path === '/api/devices/hk/firmware' ? {self.FIRMWARE}
              : req.path === '/api/devices/hk/firmware/check' ? harness.gate.promise : undefined);
            await harness.open('Hennenman kantoor');
            await harness.press(harness.button(byId('p-overview'), 'Check for updates'));
            const during = [document.activeElement.textContent, document.activeElement.getAttribute('aria-disabled')];
            await harness.press(document.activeElement);
            const asked = harness.sent('POST', '/api/devices/hk/firmware/check').length;
            harness.gate.resolve({found});
            await harness.flush();
            const node = document.activeElement;
            return {{during, asked, after: [node.textContent, byId('p-overview').contains(node)]}};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["during"] == ["Checking…", "true"]
        assert result["asked"] == 1, "a second press while it runs asks nothing more"
        assert result["after"] == ["Check for updates", True]

    def test_removing_a_tag_moves_focus_to_the_next_tag_then_to_the_field(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => {
              if (req.method !== 'DELETE') return undefined;
              const device = harness.db.acsDevices[0];
              const gone = decodeURIComponent(req.path.split('/').pop());
              device.tags = device.tags.filter((t) => t !== gone);
              return {status: 200, body: {tags: device.tags}};
            };
            await harness.open('WR3000 · AB-1');
            await harness.press(byId('d-more'));
            await harness.press(byId('d-tags'));
            const remove = (tag) => byId('tags-list').querySelectorAll('button')
              .find((b) => b.getAttribute('aria-label') === `Remove the tag ${tag}`);
            await harness.press(remove('first'));
            const next = document.activeElement.getAttribute('aria-label');
            await harness.press(remove('second'));
            return [next, document.activeElement.id];
            """,
            setup=FLEET + "harness.db.acsDevices[0].tags = ['first', 'second'];",
        )
        assert outcome["result"] == ["Remove the tag second", "tag-input"]

    def test_a_poll_keeps_focus_on_the_row_the_chip_and_the_panel(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => (req.path === '/api/devices/hk/firmware' ? {self.FIRMWARE} : undefined);
            const rowButton = byId('rows').querySelector('.row-btn');
            rowButton.focus();
            await loadRouters({{poll: true}});
            const row = [document.activeElement === rowButton, document.activeElement.textContent];
            harness.db.devices[2].status = {{online: true}};
            await loadRouters({{poll: true}});
            const redrawn = [document.activeElement !== rowButton, document.activeElement.textContent,
                             harness.row('Tenda shop').children[2].textContent];
            const chip = byId('status-chips').querySelector('[data-status=offline]');
            chip.focus();
            await loadRouters({{poll: true}});
            const chipKept = document.activeElement === chip;
            await harness.open('Hennenman kantoor');
            harness.button(byId('p-overview'), 'Check for updates').focus();
            await loadRouters({{poll: true}});
            const node = document.activeElement;
            return {{row, redrawn, chipKept, panel: [node.textContent, byId('p-overview').contains(node)]}};
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == {
            # Nothing new leaves the row alone; a change redraws it, and focus follows its router.
            "row": [True, "Hennenman kantoor"], "redrawn": [True, "Hennenman kantoor", "Online"],
            "chipKept": True, "panel": ["Check for updates", True],
        }


@needs_node
class TestKeyboardAndReasons:
    def test_why_an_action_is_unavailable_is_shown_as_text(self, tmp_path: Path):
        # A disabled button is out of the tab order and has no hover on a touch screen, so a title is not enough.
        outcome = run_page(
            tmp_path,
            """
            const why = () => [byId('d-why').hidden, byId('d-why').textContent];
            await harness.open('Tower 3 office');
            const refused = why();
            const described = byId('d-reboot').getAttribute('aria-describedby');
            harness.db.devices[1].status = {online: true};
            await loadRouters();
            const unsupported = [why(), byId('p-overview').textContent];
            await harness.open('Hennenman kantoor');
            const free = byId('d-reboot').getAttribute('aria-describedby');
            return {refused, described, unsupported, fine: why(), free};
            """,
            setup=NO_ACS,
        )
        result = outcome["result"]
        assert result["refused"] == [False, (
            "Change Wi-Fi, Refresh and Reboot: The router refused SkyRouter's login. "
            "Fix the router admin password under More first."
        )]
        assert result["described"] == "d-why"
        (hidden, text), overview = result["unsupported"]
        assert hidden is False
        assert text.startswith("Change Wi-Fi: TP-Link routers on this web page cannot change their Wi-Fi from here")
        assert "Only Cudy routers on their web page can check for updates from here" in overview
        assert result["fine"] == [True, ""] and result["free"] is None

    def test_the_more_menu_closes_when_focus_leaves_it(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.open('Hennenman kantoor');
            await harness.press(byId('d-more'));
            const opened = [byId('d-menu').hidden, document.activeElement.id];
            byId('d-more-wrap').dispatch('focusout', {relatedTarget: byId('d-admin')});
            const inside = byId('d-menu').hidden;
            byId('d-more-wrap').dispatch('focusout', {relatedTarget: byId('t-overview')});
            return [opened, inside, byId('d-menu').hidden, byId('d-more').getAttribute('aria-expanded')];
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == [[False, "d-admin"], False, True, "false"]

    def test_arrow_keys_move_between_tabs_and_between_radio_buttons(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const step = async (key) => {
              harness.key(key);
              await harness.flush();
              const node = document.activeElement;
              return node.id || node.dataset.band || node.dataset.target;
            };
            await harness.open('Hennenman kantoor');
            byId('t-overview').focus();
            const tabs = [await step('ArrowRight'), byId('p-devices').hidden,
                          byId('t-devices').getAttribute('tabindex'), byId('t-overview').getAttribute('tabindex')];
            tabs.push(await step('End'), await step('ArrowRight'), await step('Home'), await step('ArrowLeft'));
            await harness.press(byId('d-wifi'));
            byId('band-seg').querySelector('[data-band=both]').focus();
            const moved = await step('ArrowRight');
            const band = [moved, byId('band-seg').querySelector('[data-band="2.4"]').getAttribute('aria-checked')];
            await harness.press(byId('wifi-cancel'));
            await harness.go('#maintenance');
            const sub = [byId('mt-plans').getAttribute('tabindex'), byId('mt-firmware').getAttribute('tabindex')];
            byId('mt-plans').focus();
            sub.push(await step('ArrowRight'), byId('mp-firmware').hidden);
            await harness.press(byId('mt-plans'));
            await harness.press(byId('new-plan'));
            const all = byId('p-target').querySelector('[data-target=all]');
            const target = [all.getAttribute('tabindex')];
            all.focus();
            target.push(await step('ArrowRight'));
            target.push(byId('p-target').querySelector('[data-target=direct]').getAttribute('tabindex'));
            return {tabs, band, sub, target};
            """,
            setup=NO_ACS,
        )
        assert outcome["result"] == {
            "tabs": ["t-devices", False, "0", "-1", "t-history", "t-overview", "t-overview", "t-history"],
            "band": ["2.4", "true"],
            "sub": ["0", "-1", "mt-firmware", False],
            # The managed choice is hidden without TR-069, so the arrow goes past it.
            "target": ["0", "direct", "0"],
        }

    def test_a_network_says_only_what_is_known_about_it(self, tmp_path: Path):
        detail = {"wifi": [
            {"band": "2.4GHz", "ssid": "CustomerA-WiFi", "security": "wpa2", "clients": 4, "enabled": True},
            {"band": "5GHz", "ssid": "CustomerA-WiFi-5G", "enabled": False},
        ], "clients": []}
        outcome = run_page(
            tmp_path,
            """
            const bands = () => byId('p-overview').querySelectorAll('.band').slice(0, 2).map((b) => b.textContent);
            await harness.open('Hennenman kantoor');
            const direct = bands();
            await harness.open('WR3000 · AB-1');
            return [direct, bands()];
            """,
            setup=FLEET + f"harness.db.acsDetail[{json.dumps(ACS_ID)}] = {json.dumps(detail)};",
        )
        direct, managed = outcome["result"]
        # A direct router reports neither, so it says nothing rather than "— · no data".
        assert direct == ["Name not reported2.4 GHz", "Name not reported5 GHz"]
        assert managed == ["CustomerA-WiFi2.4 GHzwpa2 · 4 devices", "CustomerA-WiFi-5G5 GHzswitched off"]


# --- what the page reads, and what it concludes -----------------------------------------------


@needs_node
class TestRouterLoads:
    def test_a_page_asked_for_during_a_poll_is_still_read(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.gate = harness.deferred();
            harness.handler = (req) => (req.path.startsWith('/api/devices?') ? harness.gate.promise : undefined);
            await harness.advance(30000);
            await harness.press(byId('acs-next'));
            harness.handler = () => undefined;
            harness.gate.resolve();
            await harness.flush();
            return harness.paths().filter((p) => p.startsWith('GET /api/acs/devices?skip='));
            """,
            setup=FLEET + "harness.db.acsTotal = 450;",
        )
        assert outcome["result"] == [
            "GET /api/acs/devices?skip=0&limit=200",
            "GET /api/acs/devices?skip=0&limit=200",
            "GET /api/acs/devices?skip=200&limit=200",
        ]

    def test_a_router_removed_during_a_poll_does_not_come_back(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            // What the poll read before the router was removed.
            const before = {status: 200, body: {devices: JSON.parse(JSON.stringify(harness.db.devices))}};
            const poll = harness.deferred();
            const reload = harness.deferred();
            const gates = [poll, reload];
            harness.handler = (req) => (req.path.startsWith('/api/devices?') && gates.length ? gates.shift().promise
                                        : undefined);
            await harness.advance(30000);
            await harness.open('Tenda shop');
            await harness.press(byId('d-more'));
            await harness.press(byId('d-remove'));
            harness.db.devices = harness.db.devices.filter((d) => d.id !== 'td');
            await harness.press(byId('confirm-ok'));
            const names = () => harness.rows().map((r) => r[0].split('  ')[0]);
            poll.resolve(before);
            await harness.flush();
            // The poll's answer predates the removal, so it is not drawn while the list is read again.
            const between = names();
            reload.resolve();
            await harness.flush();
            return [between, names(), harness.paths().filter((p) => p.startsWith('GET /api/devices?')).length];
            """,
            setup=NO_ACS,
        )
        remaining = ["Hennenman kantoor", "Tower 3 office"]
        assert outcome["result"] == [remaining, remaining, 3]

    def test_an_acs_that_could_not_be_asked_at_load_is_asked_again(self, tmp_path: Path):
        # Only a 503 saying configured: false means TR-069 is off; an unreachable server says nothing.
        outcome = run_page(
            tmp_path,
            """
            const first = [harness.rows().length, byId('kind-seg').hidden, byId('routers-notes').textContent];
            await harness.advance(30000);
            return {first, rows: harness.rows().length, kindSeg: byId('kind-seg').hidden,
                    notes: byId('routers-notes').textContent,
                    asked: harness.paths().filter((p) => p === 'GET /api/acs').length};
            """,
            setup=FLEET + """
            let unanswered = true;
            harness.handler = (req) => {
              if (req.path !== '/api/acs' || !unanswered) return undefined;
              unanswered = false;
              return {unreachable: true};
            };
            """,
        )
        result = outcome["result"]
        rows, segment_hidden, notes = result["first"]
        assert rows == 3 and segment_hidden is True
        assert "whether TR-069 management is on" in notes
        assert result["rows"] == 5 and result["kindSeg"] is False and result["asked"] == 2
        assert "whether TR-069 management is on" not in result["notes"]

    @pytest.mark.parametrize("where", ["routers-notes", "rows"])
    def test_try_again_asks_whether_tr069_is_on_while_that_is_unknown(self, tmp_path: Path, where):
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = () => undefined;
            await harness.press(harness.button(byId('{where}'), 'Try again'));
            return {{rows: harness.rows().map((r) => r[0].split('  ')[0]), kindSeg: byId('kind-seg').hidden,
                     resumed: harness.paths().includes('GET /api/acs/jobs?active=true')}};
            """,
            # Nothing answers at first, so the list fails too and offers its own Try again.
            setup=FLEET + """
            harness.handler = (req) => (req.path === '/api/acs' || req.path.startsWith('/api/devices?')
              ? {unreachable: true} : undefined);
            """,
        )
        result = outcome["result"]
        assert len(result["rows"]) == 5 and "WR3000 · AB-1" in result["rows"]
        assert result["kindSeg"] is False and result["resumed"] is True

    def test_why_check_now_is_unavailable_is_written_in_the_table(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.go('#maintenance');
            await harness.press(byId('mt-firmware'));
            const row = byId('fw-rows').children.find((tr) => tr.dataset.key === 'direct:t3');
            return [row.children[1].textContent, harness.button(row, 'Check now').disabled];
            """,
            setup=NO_ACS + "harness.db.devices[1].status = {online: true, firmware: '0.9.1'};",
        )
        assert outcome["result"] == ["0.9.1Only Cudy routers on their web page can check for updates from here", True]

    def test_only_connected_hosts_count_for_a_managed_router(self, tmp_path: Path):
        # As maintenance.py counts them for a plan's client limit: a host with active: false has left.
        detail = {"clients": [
            {"hostname": "Phone", "ip": "192.168.1.20", "active": True},
            {"hostname": "OldLaptop", "ip": "192.168.1.21", "active": False},
            {"hostname": "GoneTV", "ip": "192.168.1.22", "active": False},
            {"hostname": "Printer", "ip": "192.168.1.23"},
        ]}
        outcome = run_page(
            tmp_path,
            """
            await harness.open('WR3000 · AB-1');
            const clients = harness.row('WR3000 · AB-1').children[4].textContent;
            await harness.press(byId('t-devices'));
            return [clients, byId('p-devices').textContent];
            """,
            setup=FLEET + f"harness.db.acsDetail[{json.dumps(ACS_ID)}] = {json.dumps(detail)};",
        )
        clients, devices = outcome["result"]
        assert clients == "2"
        assert "Phone" in devices and "Printer" in devices
        assert "OldLaptop" not in devices and "GoneTV" not in devices

    def test_last_seen_is_when_a_direct_router_last_answered(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const seen = (name) => harness.row(name).children[5].textContent;
            const never = seen('Tenda shop');
            await harness.open('Hennenman kantoor');
            harness.handler = (req) => (req.path === '/api/devices/hk/status' ? {status: 200, body: {device: 'hk',
              status: {online: false, error: 'timed out', checked_at: new Date().toISOString()}}} : undefined);
            await harness.press(byId('d-refresh'));
            return [never, seen('Hennenman kantoor'), harness.row('Hennenman kantoor').children[2].textContent];
            """,
            setup=NO_ACS + """
            harness.db.devices[0].last_seen = minutesAgo(120);
            harness.db.devices[2].last_seen = '';
            harness.db.devices[2].status.checked_at = minutesAgo(0);
            """,
        )
        # A check that found the router offline is not a sighting of it.
        assert outcome["result"] == ["Never", "2 h ago", "Offline"]


@needs_node
class TestPlanReach:
    """A plan acts on every adopted TR-069 router it covers, not only the page of them the list holds."""

    SCENARIO = """
        await harness.go('#maintenance');
        const card = () => byId('plans').querySelector('.plan');
        const line = card().querySelector('dl').children[1].textContent;
        await harness.press(harness.button(card(), 'Run now'));
        const asked = byId('confirm-text').textContent;
        await harness.press(byId('confirm-cancel'));
        await harness.press(harness.button(card(), 'Edit'));
        return [line, asked, byId('p-target-count').textContent];
        """
    SEARCH = "byId('acs-tag').value = 'shop'; await harness.submit(byId('acs-search')); await harness.flush();"

    def reach(self, tmp_path: Path, plan: dict, before: str = "", setup: str = "") -> list[str]:
        return run_page(
            tmp_path, before + self.SCENARIO, setup=FLEET + setup + f"harness.db.plans = [{json.dumps(plan)}];",
        )["result"]

    def test_with_every_router_listed_the_count_is_exact(self, tmp_path: Path):
        line, asked, hint = self.reach(tmp_path, PLAN)
        assert line == "All routers (5)"
        assert asked.startswith("It acts on 5 routers straight away")
        assert hint == "5 routers right now; new ones that match are included automatically."

    @pytest.mark.parametrize("narrowed", ["search", "more than a page"])
    def test_a_narrowed_list_does_not_claim_a_count(self, tmp_path: Path, narrowed):
        before, setup = (self.SEARCH, "") if narrowed == "search" else ("", "harness.db.acsTotal = 450;")
        listed = 4 if narrowed == "search" else 5
        line, asked, hint = self.reach(tmp_path, PLAN, before, setup)
        assert line == f"All routers ({listed} listed, plus any managed routers not listed)"
        assert asked.startswith(
            f"It acts on {listed} listed routers and any managed routers the list does not show, straight away"
        )
        assert hint == (
            f"{listed} routers listed, plus any managed routers not listed; new ones that match are included "
            "automatically."
        )

    def test_a_plan_naming_a_managed_router_the_list_does_not_show(self, tmp_path: Path):
        named = {**PLAN, "targets": {"all": False, "groups": [], "devices": [], "acs_devices": [ACS_ID]}}
        line, asked, _ = self.reach(tmp_path, named, self.SEARCH)
        assert line == "Chosen routers (0 listed, plus any managed routers not listed)"
        assert asked.startswith("It acts on 0 listed routers and any managed routers the list does not show")

    def test_a_plan_for_direct_routers_only_still_counts_them(self, tmp_path: Path):
        direct_plan = {**PLAN, "targets": {"all": False, "groups": ["direct"], "devices": [], "acs_devices": []}}
        line, asked, _ = self.reach(tmp_path, direct_plan, self.SEARCH)
        assert line == "Direct (3)" and asked.startswith("It acts on 3 routers straight away")


# --- the online count on the Connected devices tab --------------------------------------


@needs_node
class TestOnlineCount:
    """The Connected devices tab says, in small, how many devices are online."""

    CLIENTS = [{"name": "Phone", "cells": ["1", "Phone", "10.20.10.21", "aa:bb"]},
               {"name": "Laptop", "cells": ["2", "Laptop", "10.20.10.22", "aa:cc"]}]
    SCENARIO = """
        await harness.open(%s);
        const count = byId('t-devices-count');
        return {text: count.textContent, hidden: count.hidden, tab: byId('t-devices').textContent.trim(),
                overview: byId('t-overview').getAttribute('aria-selected'), paths: harness.paths()};
        """

    def _direct(self, tmp_path: Path, name: str, clients: list) -> dict:
        return run_page(
            tmp_path,
            self.SCENARIO % json.dumps(name),
            setup=NO_ACS + f"""
            harness.handler = (req) => {{
              if (req.path.endsWith('/clients')) return {reply({"clients": clients})};
            }};
            """,
        )["result"]

    def test_a_direct_router_shows_its_count_before_the_tab_is_opened(self, tmp_path: Path):
        result = self._direct(tmp_path, "Hennenman kantoor", self.CLIENTS)
        assert result["overview"] == "true", "the count is read while the Overview is showing"
        assert (result["text"], result["hidden"]) == ("2 online", False)
        assert result["tab"] == "Connected devices 2 online"
        assert result["paths"].count("GET /api/devices/hk/clients") == 1

    def test_a_router_with_nobody_connected_says_0_online(self, tmp_path: Path):
        result = self._direct(tmp_path, "Hennenman kantoor", [])
        assert (result["text"], result["hidden"]) == ("0 online", False)

    @pytest.mark.parametrize("name", ["Tenda shop", "Tower 3 office"])
    def test_an_offline_or_refused_direct_router_is_not_asked_and_shows_no_count(self, tmp_path: Path, name: str):
        result = self._direct(tmp_path, name, self.CLIENTS)
        assert (result["text"], result["hidden"]) == ("", True)
        assert result["tab"] == "Connected devices"
        assert not [path for path in result["paths"] if path.endswith("/clients")]

    def test_a_managed_router_counts_only_hosts_still_connected(self, tmp_path: Path):
        detail = {"clients": [{"mac": "aa", "hostname": "Laptop", "active": True},
                              {"mac": "bb", "hostname": "Phone"},
                              {"mac": "cc", "hostname": "Left an hour ago", "active": False}]}
        result = run_page(
            tmp_path,
            self.SCENARIO % json.dumps("WR3000 · AB-1"),
            setup=FLEET + f"harness.db.acsDetail[{json.dumps(ACS_ID)}] = {json.dumps(detail)};",
        )["result"]
        assert (result["text"], result["hidden"]) == ("2 online", False)

    def test_an_offline_managed_router_shows_no_count(self, tmp_path: Path):
        result = run_page(tmp_path, self.SCENARIO % json.dumps("WR1300 · CD1"), setup=FLEET)["result"]
        assert (result["text"], result["hidden"]) == ("", True)
