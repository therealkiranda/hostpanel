'use strict';
// Minimal Unix-socket RPC client. Caller must provide a request already validated against the protocol.
const net = require('net');
const crypto = require('crypto');
const { validateRequest } = require('./privileged-protocol');
function call(operation, args, options = {}) {
  const request = { id: crypto.randomBytes(16).toString('hex'), version: 1, operation, args };
  validateRequest(request);
  const socketPath = options.socketPath || process.env.HP_HELPER_SOCKET || '/run/hostpanel/privileged.sock';
  const timeoutMs = Math.min(10000, Math.max(250, Number(options.timeoutMs) || 5000));
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let data = '', finished = false;
    const fail = (e) => { if (finished) return; finished = true; socket.destroy(); reject(e instanceof Error ? e : new Error(String(e))); };
    socket.setTimeout(timeoutMs, () => fail(new Error('Privileged helper timed out')));
    socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (Buffer.byteLength(data) > 8192) return fail(new Error('Helper response too large'));
      const i = data.indexOf('\n'); if (i < 0) return;
      let response; try { response = JSON.parse(data.slice(0, i)); } catch (e) { return fail(new Error('Invalid helper response')); }
      if (response.version !== 1 || response.id !== request.id || typeof response.ok !== 'boolean') return fail(new Error('Helper response did not match request'));
      finished = true; socket.end();
      if (!response.ok) return reject(new Error(String(response.error || 'Privileged operation failed')));
      resolve(response.result);
    });
    socket.on('error', fail);
    socket.on('end', () => { if (!finished) fail(new Error('Helper closed without a response')); });
  });
}
module.exports = { call };
