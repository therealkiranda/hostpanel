'use strict';
const fs = require('fs');
const path = require('path');
const template = fs.readFileSync(path.join(__dirname, '..', 'lib', 'tpl', 'site-static.tpl'), 'utf8');
if (!template.includes('root {{DOCROOT}};')) throw new Error('Static document-root placeholder missing');
if (!template.includes('index index.html index.htm;')) throw new Error('Static index declaration missing');
if (!template.includes('try_files $uri $uri/ =404;')) throw new Error('Static request handling missing');
if (/fastcgi_pass|php-fpm|index\.php/.test(template)) throw new Error('Static template must not invoke PHP');
console.log('Static Nginx template checks passed.');
