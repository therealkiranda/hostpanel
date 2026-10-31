'use strict';
// The application catalog. Adding an application = adding an entry here plus a small handler module that exports
// validate(input), install(ctx) and fields(env) (see wordpress.js). The engine does the rest (checks, rollback, record).
const wordpress = require('./wordpress');
const laravel = require('./laravel');

const APPS = [
  {
    id: 'wordpress', dbPrefix: 'wp', name: 'WordPress', category: 'CMS & blogs', status: 'stable', icon: 'wordpress',
    summary: 'The most popular website, blog and shop platform. Installs the latest stable release, creates the database and the administrator account.',
    siteTypes: ['php'], siteType: 'php', needsDb: true, subfolder: true, handler: wordpress
  },
  {
    id: 'laravel', dbPrefix: 'lv', name: 'Laravel', category: 'Frameworks', status: 'stable', icon: 'laravel',
    summary: 'A fresh Laravel application (latest stable release) created with Composer, connected to its own database and migrated. For developers.',
    siteTypes: ['laravel'], siteType: 'laravel', needsDb: true, subfolder: false, handler: laravel
  }
];

const list = () => APPS.slice();
const get = (id) => APPS.find((a) => a.id === String(id)) || null;

module.exports = { list, get };
