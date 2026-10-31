'use strict';
// HostPanel UI helpers: layout, icons, small components. All output is escaped HTML strings.
const { esc, VERSION } = require('./core');

const I = {
  logo: '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="1.2" fill="currentColor"/><circle cx="8" cy="12" r="1.2" fill="currentColor"/><circle cx="8" cy="18" r="1.2" fill="currentColor"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  db: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  archive: '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5" rx="1"/><line x1="10" y1="12" x2="14" y2="12"/>',
  clock: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  update: '<polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
  server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
  list: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
  sliders: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  out: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  menu: '<line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  apps: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>',
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
};
const svg = (n) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + I[n] + '</svg>';

const NAV = [
  ['Overview', [['/', 'Dashboard', 'grid'], ['/sites', 'Websites', 'globe'], ['/files', 'File Manager', 'folder'], ['/databases', 'Databases', 'db']]],
  ['Operate', [['/backups', 'Backups', 'archive'], ['/cron', 'Cron Jobs', 'clock'], ['/services', 'Services', 'server'], ['/tasks', 'Tasks', 'list']]],
  ['Protect', [['/security', 'Security', 'shield'], ['/updates', 'Updates', 'update'], ['/audit', 'Audit Log', 'file']]],
  ['Manage', [['/users', 'Clients', 'users'], ['/settings', 'Settings', 'sliders'], ['/account', 'Account', 'user']]]
];
const NAV_CLIENT = [
  ['Your websites', [['/', 'Dashboard', 'grid'], ['/sites', 'Websites', 'globe'], ['/files', 'File Manager', 'folder'], ['/databases', 'Databases', 'db']]],
  ['Operate', [['/backups', 'Backups', 'archive'], ['/cron', 'Cron Jobs', 'clock'], ['/tasks', 'Tasks', 'list']]],
  ['Manage', [['/account', 'Account', 'user']]]
];
const isActive = (href, path) => (href === '/' ? path === '/' : path === href || path.startsWith(href + '/'));

function layout(req, title, body, opts) {
  opts = opts || {};
  const f = req.session && req.session.flash; if (f) delete req.session.flash;
  const asset = '?v=' + VERSION;
  const head = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">' +
    '<title>' + esc(title) + ' - HostPanel</title><link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/app.css' + asset + '">' + (opts.head || '') + '<script src="/app.js' + asset + '" defer></script></head><body>';
  const flash = f ? (f.m && f.m.indexOf('\n') >= 0 && f.t === 'ok'
    ? '<div class="flash ok sec" id="flashmsg">' + esc(f.m) + '<button class="g s" data-act="copy" data-target="#flashmsg">Copy</button></div>'
    : '<div class="flash ' + (f.t === 'ok' ? 'ok' : 'err') + '">' + esc(f.m) + '</div>') : '';
  if (!req.session || !req.session.user || opts.bare) return head + '<div class="loginbg"><div>' + flash + body + '</div></div></body></html>';
  const side = (req.session.role === 'customer' ? NAV_CLIENT : NAV).map((g) => '<div class="nav-h">' + g[0] + '</div>' + g[1].map((n) => '<a class="nav' + (isActive(n[0], req.path) ? ' active' : '') + '" href="' + n[0] + '">' + svg(n[2]) + n[1] + '</a>').join('')).join('');
  return head + '<div class="app"><aside class="side"><div class="brand"><div class="logo">' + svg('logo') + '</div><div>HostPanel<small class="muted">' + (req.session.role === 'customer' ? esc(req.session.user) : 'Server control') + ' &middot; v' + VERSION + '</small></div></div>' + side +
    '<div class="foot"><form method="post" action="/logout">' + csrf(req) + '<button class="g s">Sign out</button></form></div></aside>' +
    '<div class="main"><header class="top"><button class="iconbtn" id="menu" data-act="menu" type="button" aria-label="Menu">' + svg('menu') + '</button><h1>' + esc(title) + '</h1>' +
    (opts.pill ? '<span class="pill">' + esc(opts.pill) + '</span>' : '') +
    '<button class="iconbtn" data-act="theme" type="button" aria-label="Toggle theme">' + svg('moon') + '</button></header><main class="content">' + flash + body + '</main></div></div></body></html>';
}
const csrf = (req) => '<input type="hidden" name="_csrf" value="' + esc(req.session.csrf) + '">';
const q = (o) => Object.keys(o).map((k) => k + '=' + encodeURIComponent(o[k])).join('&');
// small inline form-button
const fbtn = (req, action, fields, label, cls, attrs) => '<form class="in" method="post" action="' + action + '" ' + (attrs || '') + '>' + csrf(req) +
  Object.keys(fields || {}).map((k) => '<input type="hidden" name="' + k + '" value="' + esc(fields[k]) + '">').join('') + '<button class="s ' + (cls || 'g') + '">' + label + '</button></form>';
const badge = (text, kind) => '<span class="badge ' + (kind || '') + '">' + (kind ? '<i class="dot"></i>' : '') + esc(text) + '</span>';
const meter = (label, value, pct) => '<div class="card"><small>' + esc(label) + '</small><div class="meter"><div class="ring' + (pct >= 90 ? ' hot' : '') + '" data-p="' + pct + '"><b>' + pct + '%</b></div><div class="big">' + esc(value) + '</div></div></div>';
const stat = (label, value, cls) => '<div class="card"><small>' + esc(label) + '</small><div class="big ' + (cls || '') + '">' + esc(value) + '</div></div>';
const field = (label, input, hint) => '<div class="field"><label>' + label + '</label>' + input + (hint ? '<small>' + hint + '</small>' : '') + '</div>';
const sel = (name, opts, cur) => '<select name="' + name + '">' + opts.map((o) => '<option value="' + esc(o[0]) + '"' + (String(o[0]) === String(cur) ? ' selected' : '') + '>' + esc(o[1]) + '</option>').join('') + '</select>';
const table = (head, rows, empty) => '<div class="wrap"><table><thead><tr>' + head.map((h) => '<th>' + h + '</th>').join('') + '</tr></thead><tbody>' +
  (rows.length ? rows.join('') : '<tr><td colspan="' + head.length + '" class="empty">' + (empty || 'Nothing here yet') + '</td></tr>') + '</tbody></table></div>';

const FAVICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7c5cff"/><stop offset=".55" stop-color="#3b82f6"/><stop offset="1" stop-color="#22d3ee"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#g)"/><g stroke="#fff" stroke-width="5" stroke-linecap="round"><path d="M16 22h32M16 32h32M16 42h32"/></g></svg>';

module.exports = { layout, csrf, q, fbtn, badge, meter, stat, field, sel, table, svg, FAVICON };
