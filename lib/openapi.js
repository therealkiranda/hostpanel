'use strict';
// OpenAPI 3.1 description of /api/v1, served at /api/v1/openapi.json (no key needed; it describes, it does not expose).
function buildSpec(version) {
  const err = { description: 'Error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } };
  const domain = { name: 'domain', in: 'path', required: true, schema: { type: 'string', example: 'example.com' } };
  const ok = (ref, d) => ({ description: d || 'OK', content: { 'application/json': { schema: { $ref: '#/components/schemas/' + ref } } } });
  const body = (ref) => ({ required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/' + ref } } } });
  const errs = { 401: err, 403: err, 404: err, 409: err, 422: err, 429: err };
  return {
    openapi: '3.1.0',
    info: { title: 'HostPanel billing API', version: String(version), description: 'Provision and manage hosting services from billing software. One service = one client login + one website. Send Authorization: Bearer hpk_... on every call.' },
    servers: [{ url: 'https://YOUR-PANEL-ADDRESS:8443', description: 'Your panel (or https://panel.yourdomain.com when a panel domain is set)' }],
    security: [{ bearer: [] }],
    paths: {
      '/api/v1/ping': { get: { summary: 'Check the key', responses: { 200: { description: 'OK' }, 401: err } } },
      '/api/v1/server': { get: { summary: 'Server facts, installed PHP versions, load', responses: { 200: ok('Server'), 401: err } } },
      '/api/v1/tasks/current': { get: { summary: 'Status of the background task (backups, deletes)', responses: { 200: ok('Task'), 401: err } } },
      '/api/v1/services': {
        get: { summary: 'List services', parameters: [{ name: 'externalId', in: 'query', schema: { type: 'string' } }, { name: 'status', in: 'query', schema: { enum: ['active', 'suspended'] } }, { name: 'username', in: 'query', schema: { type: 'string' } }, { name: 'limit', in: 'query', schema: { type: 'integer', maximum: 200 } }, { name: 'offset', in: 'query', schema: { type: 'integer' } }], responses: { 200: { description: 'OK' }, 401: err } },
        post: { summary: 'Create a service (idempotent on domain + externalId)', description: 'Creates the client login (or reuses it when username and email match) and the website. 201 = created; 200 = it already existed for this externalId (credentials are null then).', requestBody: body('NewService'), responses: Object.assign({ 201: ok('Provisioned', 'Created'), 200: ok('Provisioned', 'Already existed') }, errs) }
      },
      '/api/v1/services/{domain}': {
        parameters: [domain],
        get: { summary: 'One service', responses: Object.assign({ 200: ok('Service') }, errs) },
        delete: { summary: 'Terminate: delete the website (a final backup is taken first unless skipBackup=1)', parameters: [{ name: 'skipBackup', in: 'query', schema: { type: 'boolean' } }], responses: Object.assign({ 200: { description: 'Deleted' }, 202: { description: 'Backup running, deletion follows; poll /tasks/current' } }, errs) }
      },
      '/api/v1/services/{domain}/suspend': { parameters: [domain], post: { summary: 'Suspend: site answers 503, SFTP/SSH/cron locked, apps stopped', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { reason: { type: 'string', maxLength: 200 } } } } } }, responses: Object.assign({ 200: ok('Service') }, errs) } },
      '/api/v1/services/{domain}/unsuspend': { parameters: [domain], post: { summary: 'Unsuspend', responses: Object.assign({ 200: ok('Service') }, errs) } },
      '/api/v1/services/{domain}/password': { parameters: [domain], post: { summary: 'Set the client panel password (12-72 characters)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['password'], properties: { password: { type: 'string', minLength: 12, maxLength: 72 } } } } } }, responses: Object.assign({ 200: { description: 'OK' } }, errs) } },
      '/api/v1/services/{domain}/sftp-password': { parameters: [domain], post: { summary: 'Generate a new SFTP password (returned once)', responses: Object.assign({ 200: { description: 'OK' } }, errs) } },
      '/api/v1/services/{domain}/plan': { parameters: [domain], post: { summary: 'Change plan name / limits (recorded and reported; see usage)', requestBody: body('PlanChange'), responses: Object.assign({ 200: ok('Service') }, errs) } },
      '/api/v1/services/{domain}/usage': { parameters: [domain], get: { summary: 'Disk usage (cached 5 min), database count, limits', responses: Object.assign({ 200: { description: 'OK' } }, errs) } },
      '/api/v1/clients/{username}': {
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        get: { summary: 'One client', responses: Object.assign({ 200: { description: 'OK' } }, errs) },
        delete: { summary: 'Delete a client login that has no services left', responses: Object.assign({ 200: { description: 'OK' } }, errs) }
      }
    },
    components: {
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer', description: 'Create keys in the panel under Billing API. Format hpk_<8 hex>_<48 hex>.' } },
      schemas: {
        Error: { type: 'object', properties: { error: { type: 'object', properties: { code: { type: 'string' }, message: { type: 'string' } } } } },
        NewService: { type: 'object', required: ['domain', 'username', 'email'], properties: {
          domain: { type: 'string' }, username: { type: 'string', description: '3-32 characters, starts with a letter' }, email: { type: 'string', format: 'email' },
          password: { type: 'string', description: 'Optional. Generated when empty (12-72 characters when given).' },
          mustChangePassword: { type: 'boolean', default: true },
          type: { enum: ['php', 'static', 'node', 'python', 'proxy'], default: 'php' }, php: { type: 'string', example: '8.4' }, port: { type: 'integer' }, cmd: { type: 'string' },
          externalId: { type: 'string', description: 'Your service id; makes retries safe.' }, plan: { type: 'string' },
          limits: { $ref: '#/components/schemas/Limits' } } },
        PlanChange: { type: 'object', properties: { plan: { type: 'string' }, limits: { $ref: '#/components/schemas/Limits' } } },
        Limits: { type: 'object', properties: { diskMb: { type: ['integer', 'null'] }, bandwidthMb: { type: ['integer', 'null'] } } },
        Service: { type: 'object', properties: { domain: { type: 'string' }, type: { type: 'string' }, status: { enum: ['active', 'suspended'] }, suspendedAt: { type: ['string', 'null'] }, suspendReason: { type: ['string', 'null'] }, externalId: { type: ['string', 'null'] }, plan: { type: ['string', 'null'] }, limits: { $ref: '#/components/schemas/Limits' }, client: { type: 'object' }, sftp: { type: 'object' } } },
        Provisioned: { type: 'object', properties: { created: { type: 'boolean' }, service: { $ref: '#/components/schemas/Service' }, credentials: { type: ['object', 'null'], description: 'Shown once. Store nothing you do not need.' } } },
        Server: { type: 'object' }, Task: { type: 'object' }
      }
    }
  };
}
module.exports = { buildSpec };
