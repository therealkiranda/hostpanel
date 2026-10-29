'use strict';
// Tiny express work-alike (test only).
const fs = require('fs');
function express() {
  const stack = [];
  const app = function (req, res) {
    const u = new URL(req.url, 'http://x');
    req.path = u.pathname; req.query = Object.fromEntries(u.searchParams); req.get = (h) => req.headers[String(h).toLowerCase()];
    res.status = (c) => { res.statusCode = c; return res; };
    res.set = (k, v) => { if (typeof k === 'object') for (const x of Object.keys(k)) res.setHeader(x, k[x]); else res.setHeader(k, v); return res; };
    res.type = (t) => { res.setHeader('Content-Type', t === 'html' ? 'text/html; charset=utf-8' : t); return res; };
    res.send = (b) => { if (!res.getHeader('Content-Type')) res.setHeader('Content-Type', typeof b === 'string' ? 'text/html; charset=utf-8' : 'application/octet-stream'); res.end(b); return res; };
    res.json = (o) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(o)); return res; };
    res.redirect = (url) => { res.statusCode = 302; res.setHeader('Location', url); res.end(); };
    res.download = (f, name) => { res.setHeader('Content-Disposition', 'attachment; filename="' + name + '"'); fs.createReadStream(f).pipe(res); };
    let i = 0;
    const next = (err) => {
      while (i < stack.length) {
        const l = stack[i++], isErr = l.fn.length === 4;
        if (err) { if (!isErr) continue; return l.fn(err, req, res, next); }
        if (isErr) continue;
        if (l.method && !(req.method === l.method || (l.method === 'GET' && req.method === 'HEAD'))) continue;
        if (l.path && l.path !== req.path) continue;
        try { return l.fn(req, res, next); } catch (e) { return next(e); }
      }
      if (err) { res.statusCode = 500; res.end('Error'); } else { res.statusCode = 404; res.end('Not found'); }
    };
    next();
  };
  app.disable = () => app;
  app.use = (fn) => { stack.push({ fn }); };
  ['get', 'post', 'put'].forEach((m) => { app[m] = (p, ...fns) => fns.forEach((fn) => stack.push({ method: m.toUpperCase(), path: p, fn })); });
  return app;
}
express.urlencoded = (o) => (req, res, next) => {
  req.body = req.body || {};
  if (!/application\/x-www-form-urlencoded/.test(req.headers['content-type'] || '') || ['GET', 'HEAD'].includes(req.method)) return next();
  const max = /(\d+)(kb|mb)/.exec(String(o.limit).toLowerCase()); const limit = max ? +max[1] * (max[2] === 'mb' ? 1048576 : 1024) : 102400;
  let n = 0; const chunks = [];
  req.on('data', (c) => { n += c.length; if (n > limit) { req.destroy(); } else chunks.push(c); });
  req.on('end', () => { req.body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8'))); next(); });
};
module.exports = express;
