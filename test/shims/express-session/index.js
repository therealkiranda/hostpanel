'use strict';
// Tiny express-session work-alike (test only): cookie id -> store, regenerate/destroy, saveUninitialized=false.
const crypto = require('crypto');
class Store {}
function session(o) {
  const store = o.store, maxAge = o.cookie.maxAge || 1800000;
  return (req, res, next) => {
    const st = { sid: null, destroyed: false, isNew: true };
    const mk = (data) => {
      const s = data || {}; s.cookie = { expires: new Date(Date.now() + maxAge) };
      Object.defineProperty(s, 'regenerate', { enumerable: false, configurable: true, value: (cb) => {
        store.destroy(st.sid, () => {}); st.sid = crypto.randomBytes(16).toString('hex'); req.sessionID = st.sid; st.isNew = true; req.session = mk({}); cb();
      } });
      Object.defineProperty(s, 'destroy', { enumerable: false, configurable: true, value: (cb) => { store.destroy(st.sid, () => {}); delete req.session; st.destroyed = true; cb && cb(); } });
      return s;
    };
    const cookies = Object.fromEntries(String(req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
    const finish = (sid, data) => {
      st.sid = sid; st.isNew = !data; req.sessionID = sid; req.session = mk(data || {});
      const wh = res.writeHead;
      res.writeHead = function (...a) {
        if (st.destroyed) res.setHeader('Set-Cookie', o.name + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict');
        else if (req.session && (Object.keys(req.session).some((k) => k !== 'cookie') || !st.isNew)) {
          store.set(st.sid, req.session, () => {});
          res.setHeader('Set-Cookie', o.name + '=' + st.sid + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + Math.floor(maxAge / 1000));
        }
        return wh.apply(this, a);
      };
      next();
    };
    const sid = cookies[o.name];
    if (sid) store.get(sid, (e, d) => (d ? finish(sid, d) : finish(crypto.randomBytes(16).toString('hex'), null)));
    else finish(crypto.randomBytes(16).toString('hex'), null);
  };
}
session.Store = Store;
module.exports = session;
