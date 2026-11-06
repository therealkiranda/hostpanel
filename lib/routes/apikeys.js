'use strict';
// Administrator: API keys for billing software. Keys are shown once, stored only as a hash, and can be limited to
// read-only access and to the billing server's IP address. Clients can never open this page (default deny in access.js).
module.exports = function registerApiKeys(d0) {
  const { app, auth, page, csrf, esc, badge, field, table, fbtn, c, load, wrap, billing, q } = d0;

  app.get('/api-keys', auth, (req, res) => {
    const d = load(), st = d.settings;
    const base = st.panelSsl && st.panelDomain ? 'https://' + st.panelDomain : 'https://' + (st.ip || 'SERVER-IP') + ':' + c.PORT;
    const keys = billing.listKeys();
    const rows = keys.map((k) => '<tr><td><b>' + esc(k.name) + '</b></td><td class="mono">' + esc(k.prefix) + '_&hellip;</td><td>' + k.scopes.map((s) => badge(s, s === 'write' ? 'warn' : '')).join(' ') +
      '</td><td class="mono">' + (k.ips.length ? esc(k.ips.join(', ')) : '<span class="muted">any address</span>') + '</td><td>' + (k.lastUsed ? esc(k.lastUsed.slice(0, 16).replace('T', ' ')) + ' <span class="muted mono">' + esc(k.lastIp) + '</span>' : '<span class="muted">never</span>') +
      '</td><td class="acts">' + fbtn(req, '/api-keys/revoke', { id: k.id }, 'Revoke', 'd', 'data-confirm="Revoke the key ' + esc(k.name) + '? Billing software using it stops working immediately."') + '</td></tr>');
    const form = '<div class="card"><h2>New key</h2><form method="post" action="/api-keys/add" data-nolock>' + csrf(req) +
      field('Name', '<input name="name" required maxlength="40" pattern="[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}" autocomplete="off" placeholder="fossbilling">', 'Where the key will be used.') +
      '<div class="check"><input type="checkbox" id="sc-r" name="scopes" value="read" checked><label for="sc-r">read &mdash; list and inspect services, usage</label></div>' +
      '<div class="check"><input type="checkbox" id="sc-w" name="scopes" value="write" checked><label for="sc-w">write &mdash; create, suspend, change, delete</label></div>' +
      field('Allowed IP addresses', '<textarea name="ips" rows="2" class="mono" placeholder="203.0.113.10" spellcheck="false"></textarea>', 'The billing server\'s address, one per line. Empty = any address (not recommended). If you limited port ' + c.PORT + ' in Settings, use the panel domain or allow the billing server there too.') +
      '<button>Create key</button></form></div>';
    const curl = 'curl -s ' + base + '/api/v1/ping \\\n  -H "Authorization: Bearer hpk_xxxxxxxx_..."\n\ncurl -s -X POST ' + base + '/api/v1/services \\\n  -H "Authorization: Bearer hpk_xxxxxxxx_..." \\\n  -H "Content-Type: application/json" \\\n  -d \'{"domain":"example.com","username":"jane","email":"jane@example.com","externalId":"svc-1001"}\'';
    const how = '<div class="card"><h2>Connect billing software</h2><dl class="kv"><dt>Base URL</dt><dd class="mono">' + esc(base) + '/api/v1</dd><dt>Auth</dt><dd class="mono">Authorization: Bearer &lt;key&gt;</dd><dt>Spec</dt><dd><a href="/api/v1/openapi.json" target="_blank" rel="noopener">openapi.json</a> (OpenAPI 3.1)</dd></dl>' +
      '<pre class="log" id="curl">' + esc(curl) + '</pre><div class="row-acts"><button class="g s" type="button" data-act="copy" data-target="#curl">Copy</button></div></div>';
    page(req, res, 'Billing API', '<div class="cols"><div class="c7">' + how + '</div><div class="c5">' + form + '</div></div>' +
      '<div class="sec-h"><h2>Keys</h2><span class="muted">' + keys.length + ' of 20</span></div>' + table(['Name', 'Key id', 'Scopes', 'Allowed from', 'Last used (UTC)', 'Actions'], rows, 'No API keys yet.'));
  });
  app.post('/api-keys/add', auth, wrap((req) => {
    const k = billing.createKey({ name: req.body.name, scopes: req.body.scopes, ips: req.body.ips });
    return 'API key created: ' + k.name + '\nKey: ' + k.token + '\n(Copy it now - only a hash is stored and it is never shown again.)';
  }, '/api-keys', 'APIKEY_ADD'));
  app.post('/api-keys/revoke', auth, wrap((req) => { billing.revokeKey(String(req.body.id)); return 'Key revoked'; }, '/api-keys', 'APIKEY_REVOKE'));
};
