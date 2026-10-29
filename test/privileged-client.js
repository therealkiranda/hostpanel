'use strict';
const assert = require('assert');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { call } = require('../lib/privileged-client');
const socketPath = path.join(os.tmpdir(), 'hp-helper-test-' + process.pid + '.sock');
const server = net.createServer((s) => {
  let data = ''; s.on('data', (b) => { data += b.toString(); if (!data.includes('\n')) return; const r = JSON.parse(data); s.end(JSON.stringify({ version: 1, id: r.id, ok: true, result: { message: 'ok' } }) + '\n'); });
});
server.listen(socketPath, async () => {
  try {
    const r = await call('nginx.test', {}, { socketPath });
    assert.equal(r.message, 'ok');
    assert.throws(() => call('exec', { command: 'id' }, { socketPath }), /not allowed/);
    console.log('privileged client request/response tests passed');
  } catch (e) { console.error(e); process.exitCode = 1; }
  finally { server.close(() => { try { fs.unlinkSync(socketPath); } catch (e) {} }); }
});
