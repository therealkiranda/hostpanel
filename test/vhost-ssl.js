'use strict';
// Manual Let's Encrypt (CloudPanel style): a new site has no certificate and nothing requests one, but its vhost
// still answers on 443 with the shared self-signed certificate (no Cloudflare 525); an issued certificate replaces it.
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const T = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-vhost-'));
process.env.HP_BASE = T + '/base'; process.env.HP_HOMES = T + '/homes'; process.env.HP_NGINX = T + '/nginx';
fs.mkdirSync(T + '/base/data', { recursive: true }); fs.mkdirSync(T + '/homes');
process.env.NODE_PATH = [process.env.NODE_PATH, path.join(__dirname, 'shims')].filter(Boolean).join(path.delimiter); require('module').Module._initPaths();
const S = require('../lib/sites');
const site = { domain: 'example.com', type: 'static', user: 'wtest', docroot: '/home/wtest/public_html', ssl: false, certNames: [], cfg: {} };

let conf = S.nginxConf(site);
assert.ok(!/listen 443|ssl_certificate/.test(conf), 'no placeholder certificate installed on the box: plain http vhost');
fs.mkdirSync(T + '/nginx/hostpanel', { recursive: true });
fs.writeFileSync(T + '/nginx/hostpanel/default.crt', 'x'); fs.writeFileSync(T + '/nginx/hostpanel/default.key', 'x');
conf = S.nginxConf(site);
assert.match(conf, /listen 443 ssl/); assert.ok(conf.includes('ssl_certificate ' + T + '/nginx/hostpanel/default.crt;'));
assert.ok(conf.includes('.well-known/acme-challenge'), 'certbot webroot challenge still served');
assert.ok(!/return 301 https/.test(conf), 'no https redirect before a real certificate exists');
assert.equal((conf.match(/server \{/g) || []).length, 1);
assert.ok(!/letsencrypt\/live/.test(conf));
// the UI no longer offers or defaults to automatic SSL
const src = fs.readFileSync(__dirname + '/../server.js', 'utf8') + fs.readFileSync(__dirname + '/../lib/routes/apps.js', 'utf8');
assert.ok(!/name="autoSsl"/.test(src) && !/id="as"/.test(src), 'no auto-SSL checkbox');
// no browser-native dialogs anywhere in the client script
const js = fs.readFileSync(__dirname + '/../public/app.js', 'utf8').replace(/\/\/.*$/gm, '');
assert.ok(!/(^|[^.\w])(alert|confirm|prompt)\(/.test(js), 'branded dialogs only');
console.log('manual SSL vhost + branded dialog checks passed');
