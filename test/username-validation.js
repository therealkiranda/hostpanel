'use strict';
const assert = require('assert');
const validate = require('../lib/routes/account').validateUsername;
for (const valid of ['kiran', 'Kiran_01', 'ops.admin', 'super-admin']) assert(validate(valid), valid + ' should be valid');
for (const invalid of ['', 'ab', 'admin user', '1admin', 'a'.repeat(33), 'admin;id']) assert(!validate(invalid), JSON.stringify(invalid) + ' should be invalid');
console.log('Administrator username validation tests passed.');
