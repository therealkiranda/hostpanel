'use strict';
// Who may open which page. The administrator can open everything. A client (customer) can only open the pages below,
// and only for websites assigned to them; everything else answers 403. This list is the FIRST gate (default deny):
// each route then checks ownership of the website / database / backup it is given.
const CUSTOMER = [
  ['GET', /^\/$/], ['GET', /^\/sites$/], ['GET', /^\/sites\/manage$/], ['GET', /^\/logs$/],
  ['POST', /^\/sites\/(ssl|ssl\/off|php|keys|sftp-reset|autossl|app)$/],
  ['GET', /^\/sites\/new\/(wordpress|laravel)$/], ['POST', /^\/sites\/new\/(wordpress|laravel)$/],
  ['GET', /^\/files(\/edit|\/download)?$/], ['POST', /^\/files\/(mkdir|touch|rename|delete|unzip|chmod|save)$/], ['PUT', /^\/files\/upload$/],
  ['GET', /^\/cron$/], ['POST', /^\/cron\/save$/],
  ['GET', /^\/databases$/], ['GET', /^\/databases\/manage$/], ['POST', /^\/databases\/(add|delete|backup|pma)$/], ['POST', /^\/databases\/user\/(add|remove|password)$/],
  ['GET', /^\/backups$/], ['GET', /^\/backups\/download$/], ['POST', /^\/backups\/(site|restore|delete)$/],
  ['GET', /^\/tasks$/], ['GET', /^\/account$/], ['POST', /^\/account$/], ['POST', /^\/logout$/]
];
const customerAllowed = (method, path) => CUSTOMER.some(([m, re]) => m === method && re.test(path));
const isCustomer = (req) => !!(req.session && req.session.role === 'customer');
// the domain a request is about, from any of the parameter names the panel uses
const domainsIn = (req) => ['domain', 'site'].reduce((acc, k) => acc.concat([req.query && req.query[k], req.body && req.body[k]]), []).map((v) => String(v || '').trim()).filter(Boolean);
module.exports = { CUSTOMER, customerAllowed, isCustomer, domainsIn };
