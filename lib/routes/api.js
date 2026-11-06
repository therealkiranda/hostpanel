'use strict';
// /api/v1 - REST API for billing software. Mounted BEFORE the session / CSRF middleware: API calls carry a bearer key
// instead of a cookie, never create a session, and are never subject to CSRF.
// A small self-contained router is used on purpose (no extra express features needed, same behaviour everywhere).
const { ApiError } = require('../billing');
const { buildSpec } = require('../openapi');

const MAX_BODY = 32 * 1024;
const FAIL_WINDOW = 15 * 60 * 1000, FAIL_MAX = 10;   // bad keys per address
const KEY_RATE = 120;                                // requests per minute per key

function readJson(req) {
  return new Promise((resolve, reject) => {
    if (['GET', 'HEAD', 'DELETE'].includes(req.method) && !req.headers['content-length']) return resolve({});
    const ct = String(req.headers['content-type'] || '');
    const len = parseInt(req.headers['content-length'] || '0', 10);
    if (len === 0) return resolve({});
    if (!/^application\/json\b/i.test(ct)) { req.resume(); return reject(new ApiError(415, 'unsupported_media_type', 'Send the body as application/json')); }
    if (len > MAX_BODY) { req.resume(); return reject(new ApiError(413, 'too_large', 'Body is too large')); }
    let n = 0; const chunks = [];
    req.on('data', (x) => { n += x.length; if (n > MAX_BODY) { req.destroy(); } else chunks.push(x); });
    req.on('error', () => reject(new ApiError(400, 'bad_request', 'Request aborted')));
    req.on('end', () => {
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('x');
        resolve(v);
      } catch (e) { reject(new ApiError(400, 'bad_json', 'Body must be a JSON object')); }
    });
  });
}

module.exports = function mountApi(app, deps) {
  const { c, billing } = deps;
  const routes = [];
  const add = (method, pattern, scope, fn) => {
    const names = []; const re = new RegExp('^/api/v1' + pattern.replace(/:([A-Za-z]+)/g, (m, n) => { names.push(n); return '([^/]+)'; }) + '$');
    routes.push({ method, pattern, re, names, scope, fn });
  };
  const fails = new Map(), rate = new Map();
  c.every(60000, () => { const t = Date.now(); for (const [k, v] of fails) { const f = v.filter((x) => t - x < FAIL_WINDOW); if (f.length) fails.set(k, f); else fails.delete(k); } rate.clear(); });

  /* ---- public ---- */
  add('GET', '/openapi.json', null, () => ({ status: 200, body: buildSpec(c.VERSION) }));
  /* ---- any valid key ---- */
  add('GET', '/ping', 'any', (ctx) => ({ status: 200, body: { ok: true, version: c.VERSION, key: ctx.key.name, scopes: ctx.key.scopes } }));
  /* ---- read ---- */
  add('GET', '/server', 'read', () => ({ status: 200, body: billing.serverInfo() }));
  add('GET', '/tasks/current', 'read', () => ({ status: 200, body: billing.task() }));
  add('GET', '/services', 'read', (ctx) => ({ status: 200, body: billing.listServices(ctx.query) }));
  add('GET', '/services/:domain', 'read', (ctx) => ({ status: 200, body: billing.getService(ctx.p.domain) }));
  add('GET', '/services/:domain/usage', 'read', (ctx) => ({ status: 200, body: billing.usage(ctx.p.domain) }));
  add('GET', '/clients/:username', 'read', (ctx) => ({ status: 200, body: billing.getClient(ctx.p.username) }));
  /* ---- write ---- */
  add('POST', '/services', 'write', (ctx) => { const r = billing.createService(ctx.body); return { status: r.created ? 201 : 200, body: r, audit: r.service.domain }; });
  add('POST', '/services/:domain/suspend', 'write', (ctx) => ({ status: 200, body: billing.suspend(ctx.p.domain, ctx.body.reason), audit: ctx.p.domain }));
  add('POST', '/services/:domain/unsuspend', 'write', (ctx) => ({ status: 200, body: billing.unsuspend(ctx.p.domain), audit: ctx.p.domain }));
  add('POST', '/services/:domain/password', 'write', (ctx) => ({ status: 200, body: billing.setClientPassword(ctx.p.domain, ctx.body.password), audit: ctx.p.domain }));
  add('POST', '/services/:domain/sftp-password', 'write', (ctx) => ({ status: 200, body: billing.resetSftp(ctx.p.domain), audit: ctx.p.domain }));
  add('POST', '/services/:domain/plan', 'write', (ctx) => ({ status: 200, body: billing.setPlan(ctx.p.domain, ctx.body), audit: ctx.p.domain }));
  add('DELETE', '/services/:domain', 'write', (ctx) => {
    const skip = ctx.query.skipBackup === '1' || ctx.query.skipBackup === 'true' || ctx.body.skipBackup === true;
    const r = billing.terminate(ctx.p.domain, { skipBackup: skip });
    return { status: skip ? 200 : 202, body: r, audit: ctx.p.domain };
  });
  add('DELETE', '/clients/:username', 'write', (ctx) => ({ status: 200, body: billing.deleteClient(ctx.p.username), audit: ctx.p.username }));

  const send = (res, status, body) => { res.status(status).json(body); };
  const fail = (res, e, extra) => {
    const status = e instanceof ApiError ? e.status : 500, code = e instanceof ApiError ? e.code : 'internal';
    if (extra && extra.retryAfter) res.set('Retry-After', String(extra.retryAfter));
    send(res, status, { error: { code, message: e instanceof ApiError ? e.message : 'Internal error' } });
  };

  app.use(async (req, res, next) => {
    if (!req.path.startsWith('/api/')) return next();
    if (req.path === '/api' || !req.path.startsWith('/api/v1/')) return send(res, 404, { error: { code: 'not_found', message: 'Unknown API version. Use /api/v1' } });
    const ip = c.cleanIp(req);
    let key = null;
    try {
      const route = routes.map((r) => { const m = r.re.exec(req.path); return m && r.method === req.method ? { r, m } : null; }).find(Boolean);
      const other = !route && routes.some((r) => r.re.test(req.path));
      if (!route) return send(res, other ? 405 : 404, { error: { code: other ? 'method_not_allowed' : 'not_found', message: other ? 'Method not allowed' : 'Unknown endpoint' } });
      const p = {}; route.r.names.forEach((n, i) => { try { p[n] = decodeURIComponent(route.m[i + 1]); } catch (e) { throw new ApiError(400, 'bad_request', 'Bad path'); } });
      if (route.r.scope) {
        const now = Date.now(), rec = (fails.get(ip) || []).filter((t) => now - t < FAIL_WINDOW);
        if (rec.length >= FAIL_MAX) return fail(res, new ApiError(429, 'too_many_failures', 'Too many invalid keys from this address. Try again later.'), { retryAfter: 900 });
        const h = String(req.headers.authorization || ''), tok = /^Bearer\s+(\S+)$/i.exec(h);
        key = tok ? billing.verifyKey(tok[1]) : null;
        if (!key) { rec.push(now); fails.set(ip, rec); c.authFail(req, 'api'); return fail(res, new ApiError(401, 'unauthorized', 'Missing or invalid API key')); }
        if (!billing.ipAllowed(key, ip)) { c.auditSys('API_IP_DENIED', key.name + ' from ' + ip); return fail(res, new ApiError(403, 'ip_not_allowed', 'This key is not allowed from ' + ip)); }
        if (route.r.scope !== 'any' && !key.scopes.includes(route.r.scope)) return fail(res, new ApiError(403, 'insufficient_scope', 'This key has no ' + route.r.scope + ' access'));
        const n = (rate.get(key.id) || 0) + 1; rate.set(key.id, n);
        if (n > KEY_RATE) return fail(res, new ApiError(429, 'rate_limited', 'Too many requests'), { retryAfter: 60 });
        billing.touchKey(key.id, ip);
      }
      const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? await readJson(req) : {};
      const out = route.r.fn({ p, body, query: req.query || {}, key, ip });
      if (out.audit !== undefined) c.audit({ socket: req.socket, headers: req.headers, session: { user: 'api:' + (key ? key.name : '-') } }, 'API ' + req.method + ' ' + route.r.pattern, out.audit);
      send(res, out.status, out.body);
    } catch (e) {
      if (!(e instanceof ApiError)) c.auditSys('API_ERROR', req.method + ' ' + req.path + ': ' + c.errMsg(e));
      fail(res, e);
    }
  });
};
