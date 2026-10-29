#!/usr/bin/env node
'use strict';
// Root-owned, closed-operation helper prototype. Keep disabled until the panel is fully migrated to
// this RPC boundary; the existing server still performs privileged work directly.
const fs = require('fs');
const net = require('net');
const path = require('path');
const { execFileSync } = require('child_process');
const { validateRequest, safeResponse } = require('./lib/privileged-protocol');
const SOCKET = process.env.HP_HELPER_SOCKET || '/run/hostpanel/privileged.sock';
const GROUP = process.env.HP_HELPER_GROUP || 'hostpanel';
const MAX = 32 * 1024;
const ALLOWED_SERVICES = new Set(['nginx', 'mysql', 'mariadb', 'cron', 'fail2ban', 'php8.2-fpm', 'php8.3-fpm', 'php8.4-fpm', 'php8.5-fpm']);
if (process.getuid && process.getuid() !== 0) { console.error('privileged-helper must run as root'); process.exit(1); }
function run(file, args) { return execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000, maxBuffer: 1024 * 1024 }); }
async function dispatch(req) {
  validateRequest(req);
  switch (req.operation) {
    case 'nginx.test': run('/usr/sbin/nginx', ['-t']); return { message: 'Nginx configuration is valid' };
    case 'nginx.reload': run('/usr/sbin/nginx', ['-t']); run('/usr/bin/systemctl', ['reload', 'nginx']); return { message: 'Nginx reloaded after successful config test' };
    case 'service.reload': {
      const service = req.args.service;
      if (!ALLOWED_SERVICES.has(service)) throw new Error('Service is not allowed');
      run('/usr/bin/systemctl', ['reload', service]);
      return { message: 'Service reloaded', service };
    }
    // Fail closed until resource operations are migrated and tested. Do not silently call the old
    // root-running site manager from this helper: that would preserve the original privilege model.
    default: throw new Error('This operation is schema-defined but not enabled in the helper yet');
  }
}
function reply(socket, obj) { try { socket.end(JSON.stringify(obj) + '\n'); } catch (e) { socket.destroy(); } }
fs.mkdirSync(path.dirname(SOCKET), { recursive: true, mode: 0o755 });
try { fs.unlinkSync(SOCKET); } catch (e) { if (e.code !== 'ENOENT') throw e; }
const server = net.createServer((socket) => {
  socket.setTimeout(5000, () => socket.destroy());
  let data = '';
  socket.on('data', (chunk) => {
    data += chunk.toString('utf8');
    if (Buffer.byteLength(data) > MAX) return reply(socket, safeResponse('0000000000000000', false, 'Request too large'));
    const i = data.indexOf('\n');
    if (i < 0) return;
    const line = data.slice(0, i);
    if (data.slice(i + 1).trim()) return reply(socket, safeResponse('0000000000000000', false, 'Only one request is allowed per connection'));
    let req;
    try { req = JSON.parse(line); } catch (e) { return reply(socket, safeResponse('0000000000000000', false, 'Invalid JSON')); }
    Promise.resolve().then(() => dispatch(req)).then((result) => reply(socket, safeResponse(req.id, true, result)), (err) => reply(socket, safeResponse(req && req.id || '0000000000000000', false, err.message || 'Operation failed')));
  });
});
server.listen(SOCKET, () => {
  fs.chmodSync(SOCKET, 0o660);
  try { execFileSync('/usr/bin/chgrp', [GROUP, SOCKET]); } catch (e) { console.error('Unable to set helper socket group; refusing unsafe socket permissions'); server.close(() => process.exit(1)); }
  console.log('HostPanel privileged helper listening on ' + SOCKET + ' (operations are allowlisted)');
});
