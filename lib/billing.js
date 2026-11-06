'use strict';
// Billing API logic (HostPanel 1.0.8). Everything the REST layer does lives here so it can be tested without HTTP:
//  - API keys (stored hashed, shown once, optional IP allow-list, read / write scopes)
//  - "services": one hosting service = a client login + one website, which is what billing software provisions
//  - suspend / unsuspend / terminate / usage
// Every command that touches the machine goes through `host`, so tests can replace it.
const crypto = require('crypto');
const net = require('net');
const { spawnSync } = require('child_process');
const tenancy = require('./tenancy');

class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const bad = (m, code) => new ApiError(422, code || 'invalid_request', m);

const SCOPES = ['read', 'write'];
const API_TYPES = ['php', 'static', 'node', 'python', 'proxy'];
const KEY_RE = /^hpk_([a-f0-9]{8})_([a-f0-9]{48})$/;
const EXT_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const PLAN_RE = /^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,63}$/;
const sha = (x) => crypto.createHash('sha256').update(String(x)).digest();
const DUMMY = sha('hostpanel-dummy-key').toString('hex');
const MAX_KEYS = 20;

function cleanLimits(v) {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'object' || Array.isArray(v)) throw bad('limits must be an object', 'invalid_limits');
  const out = {};
  for (const k of ['diskMb', 'bandwidthMb']) {
    if (v[k] === undefined) continue;                       // only the keys that were sent change
    if (v[k] === null || v[k] === '') { out[k] = null; continue; }
    const n = Number(v[k]);
    if (!Number.isInteger(n) || n < 0 || n > 100000000) throw bad('limits.' + k + ' must be a whole number of megabytes (0 = unlimited)', 'invalid_limits');
    out[k] = n;
  }
  return out;
}
const cleanPlan = (v) => { if (v === undefined || v === null || v === '') return ''; const p = String(v).trim(); if (!PLAN_RE.test(p)) throw bad('plan must be 1-64 letters, numbers, spaces or . _ : / -', 'invalid_plan'); return p; };
const cleanExt = (v) => { if (v === undefined || v === null || v === '') return ''; const x = String(v).trim(); if (!EXT_RE.test(x)) throw bad('externalId must be 1-64 characters: letters, numbers and . _ : -', 'invalid_external_id'); return x; };
const cleanReason = (v) => String(v || '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 200);

function defaultHost(deps) {
  const { c, S, runtime } = deps;
  return {
    applyNginx: (s) => S.applyNginx(s.domain + '.conf', S.nginxConf(s)),
    lockUser: (user, on) => c.sh('usermod', ['-e', on ? '1' : '', user]),   // expired account = no SFTP/SSH login, no cron
    killUser: (user) => { try { c.sh('pkill', ['-u', user]); } catch (e) {} },
    appOff: (s) => c.sh('systemctl', ['disable', '--now', runtime.unitName(s)]),
    appOn: (s) => c.sh('systemctl', ['enable', '--now', runtime.unitName(s)]),
    diskBytes: (home) => { const r = spawnSync('du', ['-sb', home], { encoding: 'utf8', timeout: 30000 }); const n = parseInt(String(r.stdout || '').split(/\s/)[0], 10); return Number.isFinite(n) ? n : null; }
  };
}

function createBilling(deps) {
  const { c, S, U, sys, runtime, tools } = deps;
  const host = Object.assign(defaultHost(deps), deps.host || {});
  const duCache = new Map();

  /* ---------------- API keys ---------------- */
  function createKey(f) {
    const name = String(f.name || '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$/.test(name)) throw bad('Key name: 1-40 letters, numbers, spaces, . _ -', 'invalid_name');
    const scopes = [].concat(f.scopes === undefined ? ['read', 'write'] : f.scopes).map(String).filter((x) => SCOPES.includes(x));
    if (!scopes.length) throw bad('Choose at least one scope', 'invalid_scope');
    if (scopes.includes('write') && !scopes.includes('read')) scopes.push('read');
    const ips = Array.isArray(f.ips) ? S.cleanIpList(f.ips.join(' ')) : S.cleanIpList(f.ips);
    const d = c.load(); d.apiKeys = d.apiKeys || [];
    if (d.apiKeys.length >= MAX_KEYS) throw bad('At most ' + MAX_KEYS + ' API keys; revoke one first', 'too_many_keys');
    if (d.apiKeys.some((k) => k.name.toLowerCase() === name.toLowerCase())) throw bad('A key with that name already exists', 'duplicate_name');
    const id = c.rand(4), secret = c.rand(24);
    d.apiKeys.push({ id, name, hash: sha(secret).toString('hex'), scopes, ips, created: new Date().toISOString(), lastUsed: '', lastIp: '' });
    c.save(d);
    return { id, name, scopes, ips, token: 'hpk_' + id + '_' + secret };
  }
  const listKeys = () => (c.load().apiKeys || []).map((k) => ({ id: k.id, name: k.name, scopes: k.scopes, ips: k.ips, created: k.created, lastUsed: k.lastUsed, lastIp: k.lastIp, prefix: 'hpk_' + k.id }));
  function revokeKey(id) {
    const d = c.load(), n = (d.apiKeys || []).length;
    d.apiKeys = (d.apiKeys || []).filter((k) => k.id !== String(id));
    if (d.apiKeys.length === n) throw new ApiError(404, 'not_found', 'Key not found');
    c.save(d);
  }
  // Returns the key record or null. Always spends one constant-time comparison, found or not.
  function verifyKey(token) {
    const m = KEY_RE.exec(String(token || ''));
    const d = c.load(), k = m ? (d.apiKeys || []).find((x) => x.id === m[1]) : null;
    const want = Buffer.from(k ? k.hash : DUMMY, 'hex'), got = sha(m ? m[2] : 'x');
    const same = want.length === got.length && crypto.timingSafeEqual(want, got);
    return k && same ? k : null;
  }
  function touchKey(id, ip) {
    const d = c.load(), k = (d.apiKeys || []).find((x) => x.id === id); if (!k) return;
    if (k.lastIp === ip && k.lastUsed && Date.now() - Date.parse(k.lastUsed) < 60000) return; // do not rewrite the database on every call
    k.lastUsed = new Date().toISOString(); k.lastIp = ip; c.save(d);
  }
  function ipAllowed(key, ip) {
    if (!key.ips || !key.ips.length) return true;
    const fam = net.isIPv6(ip) ? 'ipv6' : 'ipv4', bl = new net.BlockList();
    for (const x of key.ips) {
      const [a, bits] = x.split('/'), f = net.isIPv6(a) ? 'ipv6' : 'ipv4';
      if (bits === undefined) bl.addAddress(a, f); else bl.addSubnet(a, +bits, f);
    }
    return net.isIP(ip) ? bl.check(ip, fam) : false;
  }

  /* ---------------- views ---------------- */
  const clientOf = (d, s) => (s.ownerId && s.ownerId !== 'system' ? d.users.find((u) => u.id === s.ownerId) || null : null);
  const siteOf = (d, domain) => {
    const dom = String(domain || '').trim().toLowerCase();
    const s = S.DOMAIN_RE.test(dom) ? d.sites.find((x) => x.domain === dom) : null;
    if (!s) throw new ApiError(404, 'not_found', 'Service not found');
    return s;
  };
  const sftpHost = (d) => d.settings.panelDomain || d.settings.ip || '';
  function view(d, s) {
    const cl = clientOf(d, s);
    return {
      domain: s.domain, type: s.type, php: s.php || null, port: s.port || null,
      status: s.suspended ? 'suspended' : 'active', suspendedAt: s.suspendedAt || null, suspendReason: s.suspendReason || null,
      externalId: s.externalId || null, plan: s.plan || null, limits: s.limits || { diskMb: null, bandwidthMb: null },
      client: cl ? { username: cl.username, email: cl.email } : null,
      sftp: { host: sftpHost(d), port: 22, user: s.user }, ssl: !!s.ssl, created: s.created
    };
  }

  /* ---------------- services ---------------- */
  const busy = () => { if (c.jobRunning()) throw new ApiError(409, 'busy', 'Another task is running on this server. Retry in a minute.'); };
  function fromPanel(e) {
    if (e instanceof ApiError) return e;
    const m = c.errMsg(e);
    if (/Another task is running/.test(m)) return new ApiError(409, 'busy', 'Another task is running on this server. Retry in a minute.');
    if (/already exists|already used|belongs to|reserved/i.test(m)) return new ApiError(409, 'conflict', m);
    if (/not found/i.test(m)) return new ApiError(404, 'not_found', m);
    return new ApiError(500, 'provision_failed', m);
  }

  function createService(input) {
    input = input || {};
    const domain = String(input.domain || '').trim().toLowerCase().replace(/^www\./, '');
    if (!S.DOMAIN_RE.test(domain)) throw bad('Invalid domain', 'invalid_domain');
    const type = String(input.type || 'php');
    if (!API_TYPES.includes(type)) throw bad('type must be one of: ' + API_TYPES.join(', '), 'invalid_type');
    const externalId = cleanExt(input.externalId), plan = cleanPlan(input.plan), limits = cleanLimits(input.limits);
    const username = String(input.username || '').trim(), email = String(input.email || '').trim().toLowerCase();
    if (!tenancy.USER_RE.test(username)) throw bad('username must be 3-32 characters: letters, numbers and . _ - (start with a letter)', 'invalid_username');
    if (!S.EMAIL_RE.test(email) || email.length > 254) throw bad('A valid email is required', 'invalid_email');

    let d = c.load();
    const have = d.sites.find((x) => x.domain === domain);
    if (have) { // creating the same service twice (a retried request) is not an error
      if (externalId && have.externalId === externalId) return { created: false, service: view(d, have), credentials: null };
      throw new ApiError(409, 'domain_exists', 'A website with that domain already exists');
    }
    if (type === 'python' && !tools.TOOLS.python.ready()) throw bad('Python 3 with venv is not installed on this server', 'python_missing');
    const phpList = sys.phpVersions();
    const php = type === 'php' ? String(input.php || sys.defaultPhp(phpList)) : '';
    if (type === 'php' && !phpList.includes(php)) throw bad('PHP ' + php + ' is not installed. Installed: ' + (phpList.join(', ') || 'none'), 'invalid_php');
    busy();

    // client login: reuse an existing one (same username AND email), otherwise create it
    let user = U.findByName(d, username), newClient = false, clientPassword = null;
    if (user) {
      if (user.email !== email) throw new ApiError(409, 'client_conflict', 'That username belongs to a different client');
      if (user.active === false) throw new ApiError(409, 'client_disabled', 'That client login is disabled');
    } else {
      if (d.users.some((u) => u.email === email)) throw new ApiError(409, 'client_conflict', 'That email belongs to a different username');
      clientPassword = input.password === undefined || input.password === '' ? c.genPassword(20) : String(input.password);
      if (clientPassword.length < 12 || clientPassword.length > 72) throw bad('password must be 12-72 characters', 'invalid_password');
      try { U.add({ username, email, password: clientPassword, mustChange: input.mustChangePassword !== false }); } catch (e) { throw fromPanel(new Error(c.errMsg(e))); }
      newClient = true; user = U.findByName(c.load(), username);
    }
    let made;
    try {
      made = S.createSiteCore({ domain, type, php, port: input.port, cmd: input.cmd, ownerId: user.id });
      if (type === 'python') { const s2 = S.getSite(c.load(), domain); c.runAsync('Set up Python site ' + domain, (log) => runtime.bootstrap(s2, log)); c.setJobOwner('system'); }
    } catch (e) {
      if (newClient) { try { U.remove(user.id); } catch (x) {} }
      throw fromPanel(e);
    }
    d = c.load();
    const s = d.sites.find((x) => x.domain === domain);
    if (externalId) s.externalId = externalId;
    if (plan) s.plan = plan;
    if (limits) s.limits = Object.assign({ diskMb: null, bandwidthMb: null }, limits);
    s.createdVia = 'api'; c.save(d);
    const url = d.settings.panelSsl && d.settings.panelDomain ? 'https://' + d.settings.panelDomain : 'https://' + (d.settings.ip || 'SERVER-IP') + ':' + c.PORT;
    return {
      created: true, service: view(d, s),
      credentials: {
        sftp: { host: sftpHost(d), port: 22, user: made.site.user, password: made.pass },
        panel: newClient ? { url, username, password: clientPassword, mustChangePassword: input.mustChangePassword !== false } : { url, username, password: null }
      }
    };
  }

  const getService = (domain) => { const d = c.load(); return view(d, siteOf(d, domain)); };
  function listServices(q) {
    q = q || {};
    const d = c.load(); let list = d.sites;
    if (q.externalId) list = list.filter((s) => s.externalId === String(q.externalId));
    if (q.status === 'suspended') list = list.filter((s) => s.suspended);
    if (q.status === 'active') list = list.filter((s) => !s.suspended);
    if (q.username) { const u = U.findByName(d, q.username); list = list.filter((s) => u && s.ownerId === u.id); }
    const limit = Math.min(200, Math.max(1, parseInt(q.limit, 10) || 100)), offset = Math.max(0, parseInt(q.offset, 10) || 0);
    return { total: list.length, items: list.slice(offset, offset + limit).map((s) => view(d, s)) };
  }

  function suspend(domain, reason) {
    const d = c.load(), s = siteOf(d, domain);
    if (s.suspended) return view(d, s);
    s.suspended = true; s.suspendedAt = new Date().toISOString(); s.suspendReason = cleanReason(reason);
    try {
      host.applyNginx(s);                               // the website answers 503 from now on
      host.lockUser(s.user, true);                      // SFTP / SSH / cron login closed
    } catch (e) {
      s.suspended = false; delete s.suspendedAt; delete s.suspendReason;
      try { host.applyNginx(s); } catch (x) {}
      throw fromPanel(e);
    }
    host.killUser(s.user);
    if (runtime.KINDS[s.type]) { try { host.appOff(s); } catch (e) { c.auditSys('API_SUSPEND_APP', s.domain + ': ' + c.errMsg(e)); } }
    c.save(d); c.auditSys('API_SUSPEND', s.domain);
    return view(d, s);
  }
  function unsuspend(domain) {
    const d = c.load(), s = siteOf(d, domain);
    if (!s.suspended) return view(d, s);
    const was = { at: s.suspendedAt, why: s.suspendReason };
    s.suspended = false; delete s.suspendedAt; delete s.suspendReason;
    try {
      host.lockUser(s.user, false);
      host.applyNginx(s);
    } catch (e) { s.suspended = true; s.suspendedAt = was.at; s.suspendReason = was.why; throw fromPanel(e); }
    if (runtime.KINDS[s.type]) { try { host.appOn(s); } catch (e) { c.auditSys('API_UNSUSPEND_APP', s.domain + ': ' + c.errMsg(e)); } }
    c.save(d); c.auditSys('API_UNSUSPEND', s.domain);
    return view(d, s);
  }

  function setClientPassword(domain, password) {
    const d = c.load(), s = siteOf(d, domain), cl = clientOf(d, s);
    if (!cl) throw new ApiError(409, 'no_client', 'This service has no client login');
    password = String(password || '');
    if (password.length < 12 || password.length > 72) throw bad('password must be 12-72 characters', 'invalid_password');
    U.setPassword(cl.id, password, false);   // also signs the client out everywhere
    return { username: cl.username };
  }
  function resetSftp(domain) {
    const d = c.load(), s = siteOf(d, domain);
    try { const r = S.newSftpPassword(s.domain); return { host: sftpHost(d), port: 22, user: r.user, password: r.pass }; } catch (e) { throw fromPanel(e); }
  }
  function setPlan(domain, input) {
    input = input || {};
    const d = c.load(), s = siteOf(d, domain), plan = cleanPlan(input.plan), limits = cleanLimits(input.limits);
    if (input.plan !== undefined) s.plan = plan;
    if (limits) s.limits = Object.assign({ diskMb: null, bandwidthMb: null }, s.limits || {}, limits);
    c.save(d); return view(d, s);
  }

  function terminate(domain, opts) {
    const d = c.load(), s = siteOf(d, domain), cl = clientOf(d, s), skip = !!(opts && opts.skipBackup);
    let msg;
    try { msg = S.deleteSite(s.domain, skip, s.domain); } catch (e) { throw fromPanel(e); }
    // the client's last website is going away: close the login now (the record can be removed with DELETE /clients/{username})
    if (cl && !d.sites.some((x) => x.ownerId === cl.id && x.domain !== s.domain)) { try { U.setActive(cl.id, false); } catch (e) {} }
    c.auditSys('API_TERMINATE', s.domain);
    return { status: skip ? 'deleted' : 'deleting', message: String(msg).split('\n')[0] };
  }

  function usage(domain) {
    const d = c.load(), s = siteOf(d, domain);
    let hit = duCache.get(s.domain);
    if (!hit || Date.now() - hit.t > 300000) { hit = { t: Date.now(), b: host.diskBytes(s.home) }; duCache.set(s.domain, hit); }
    const lim = s.limits || {}, diskMb = hit.b === null ? null : Math.ceil(hit.b / 1048576);
    return {
      domain: s.domain, measuredAt: new Date(hit.t).toISOString(),
      disk: { usedBytes: hit.b, usedMb: diskMb, limitMb: lim.diskMb || null, overLimit: !!(lim.diskMb && diskMb !== null && diskMb > lim.diskMb) },
      bandwidth: { measured: false, limitMb: lim.bandwidthMb || null },
      databases: d.dbs.filter((x) => x.site === s.domain).length
    };
  }

  /* ---------------- clients ---------------- */
  function clientView(d, u) {
    return { username: u.username, email: u.email, active: u.active !== false, twoFactor: !!u.totpSecret, createdAt: u.createdAt, lastLogin: u.lastLogin || null, services: d.sites.filter((s) => s.ownerId === u.id).map((s) => s.domain) };
  }
  function getClient(username) {
    const d = c.load(), u = U.findByName(d, username);
    if (!u) throw new ApiError(404, 'not_found', 'Client not found');
    return clientView(d, u);
  }
  function deleteClient(username) {
    const d = c.load(), u = U.findByName(d, username);
    if (!u) throw new ApiError(404, 'not_found', 'Client not found');
    if (d.sites.some((s) => s.ownerId === u.id)) throw new ApiError(409, 'client_in_use', 'The client still has services; terminate them first');
    U.remove(u.id); return { deleted: true };
  }

  function serverInfo() {
    const d = c.load(), st = sys.stats();
    return {
      name: 'HostPanel', version: c.VERSION, apiVersion: 1, ip: d.settings.ip || null, panelDomain: d.settings.panelDomain || null,
      phpVersions: sys.phpVersions(), types: API_TYPES.filter((t) => t !== 'python' || tools.TOOLS.python.ready()),
      services: d.sites.length, suspended: d.sites.filter((s) => s.suspended).length,
      load: { cores: st.cores, cpuPct: Math.min(100, Math.round((parseFloat(st.load) / st.cores) * 100)), ramPct: st.ramPct, diskPct: st.diskPct }
    };
  }
  function task() {
    const j = c.getJob();
    if (!j) return { running: false, label: null, startedAt: null, endedAt: null, exitCode: null };
    return { running: !j.end, label: j.label, startedAt: new Date(j.start).toISOString(), endedAt: j.end ? new Date(j.end).toISOString() : null, exitCode: j.end ? j.code : null };
  }

  return { createKey, listKeys, revokeKey, verifyKey, touchKey, ipAllowed, createService, getService, listServices, suspend, unsuspend, setClientPassword, resetSftp, setPlan, terminate, usage, getClient, deleteClient, serverInfo, task, view };
}

module.exports = { createBilling, ApiError, SCOPES, API_TYPES, KEY_RE };
