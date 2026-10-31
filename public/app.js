/* HostPanel client script. Served as an external file (CSP forbids inline scripts). */
(function () {
  'use strict';
  var d = document, $ = function (s, r) { return (r || d).querySelector(s); }, $$ = function (s, r) { return Array.prototype.slice.call((r || d).querySelectorAll(s)); };

  // theme
  var root = d.documentElement, saved = null;
  try { saved = localStorage.getItem('hp-theme'); } catch (e) {}
  if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);
  d.addEventListener('click', function (e) {
    var t = e.target.closest ? e.target.closest('[data-act]') : null;
    if (!t) return;
    var a = t.getAttribute('data-act');
    if (a === 'theme') {
      var cur = root.getAttribute('data-theme') || (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      var next = cur === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next); try { localStorage.setItem('hp-theme', next); } catch (x) {}
    } else if (a === 'menu') { var s = $('.side'); if (s) s.classList.toggle('open'); }
    else if (a === 'copy') {
      var el = $(t.getAttribute('data-target')), txt = el ? el.textContent : '';
      if (navigator.clipboard) navigator.clipboard.writeText(txt).then(function () { t.textContent = 'Copied'; setTimeout(function () { t.textContent = 'Copy'; }, 1500); });
    }
  });
  d.addEventListener('click', function (e) { if (e.target.closest && !e.target.closest('.side') && !e.target.closest('[data-act=menu]')) { var s = $('.side.open'); if (s) s.classList.remove('open'); } });

  // meters (CSP blocks style="" attributes, but setting styles from script is allowed)
  $$('[data-w]').forEach(function (el) { var v = Math.max(0, Math.min(100, parseFloat(el.getAttribute('data-w')) || 0)); requestAnimationFrame(function () { el.style.width = v + '%'; }); });
  $$('[data-p]').forEach(function (el) { el.style.setProperty('--p', Math.max(0, Math.min(100, parseFloat(el.getAttribute('data-p')) || 0))); });

  // Branded dialogs (replace the browser's confirm/prompt/alert). Built with DOM APIs + textContent only.
  function el(tag, cls, txt) { var n = d.createElement(tag); if (cls) n.className = cls; if (txt !== undefined) n.textContent = txt; return n; }
  var ICONS = { danger: '!', warn: '!', info: 'i', ask: '?' };
  // opts: {title, message, tone:'danger'|'warn'|'info'|'ask', ok, cancel (false = hide), input:{value,label,placeholder,match,mono}, hideCancel}
  // Returns a Promise: true/false for plain dialogs, the entered string (or null) for input dialogs.
  function dialog(opts) {
    return new Promise(function (resolve) {
      var prev = d.activeElement, tone = opts.tone || 'ask';
      var ov = el('div', 'dlg-ov'), box = el('div', 'dlg dlg-' + tone);
      box.setAttribute('role', tone === 'danger' ? 'alertdialog' : 'dialog'); box.setAttribute('aria-modal', 'true');
      var tid = 'dlg-t' + Date.now(), mid = 'dlg-m' + Date.now();
      box.setAttribute('aria-labelledby', tid); box.setAttribute('aria-describedby', mid);
      var head = el('div', 'dlg-head'); head.appendChild(el('span', 'dlg-ico', ICONS[tone] || '?'));
      var ttl = el('h3', 'dlg-title', opts.title || 'Please confirm'); ttl.id = tid; head.appendChild(ttl); box.appendChild(head);
      var msg = el('div', 'dlg-msg', opts.message || ''); msg.id = mid; box.appendChild(msg);
      var inp = null;
      if (opts.input) {
        var o = opts.input, wrap = el('div', 'dlg-field');
        if (o.label) wrap.appendChild(el('label', null, o.label));
        if (o.match) { var tag = el('code', 'dlg-match', o.match); wrap.appendChild(tag); }
        inp = el('input', o.mono || o.match ? 'mono' : ''); inp.type = 'text'; inp.value = o.value || ''; inp.autocomplete = 'off';
        inp.setAttribute('autocapitalize', 'off'); inp.spellcheck = false; if (o.placeholder) inp.placeholder = o.placeholder;
        wrap.appendChild(inp); box.appendChild(wrap);
      }
      var foot = el('div', 'dlg-foot'), cancel = null;
      if (!opts.hideCancel) { cancel = el('button', 'g', opts.cancel || 'Cancel'); cancel.type = 'button'; foot.appendChild(cancel); }
      var ok = el('button', tone === 'danger' ? 'dlg-danger' : '', opts.ok || 'OK'); ok.type = 'button'; foot.appendChild(ok);
      box.appendChild(foot); ov.appendChild(box); d.body.appendChild(ov); d.body.classList.add('dlg-open');
      function valid() { return !(opts.input && opts.input.match) || inp.value.trim() === opts.input.match; }
      function sync() { if (opts.input && opts.input.match) { ok.disabled = !valid(); box.classList.toggle('dlg-okmatch', valid()); } }
      function close(v) {
        d.removeEventListener('keydown', onKey, true); ov.remove(); d.body.classList.remove('dlg-open');
        if (prev && prev.focus) { try { prev.focus(); } catch (x) {} }
        resolve(v);
      }
      function accept() { if (!valid()) { box.classList.remove('dlg-shake'); void box.offsetWidth; box.classList.add('dlg-shake'); return; } close(inp ? inp.value : true); }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(inp ? null : false); }
        else if (e.key === 'Enter' && e.target !== cancel) { e.preventDefault(); e.stopPropagation(); accept(); }
        else if (e.key === 'Tab') {
          var f = $$('input,button:not(:disabled)', box); if (!f.length) return;
          var i = f.indexOf(d.activeElement);
          if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
          else if (!e.shiftKey && (i === f.length - 1 || i < 0)) { e.preventDefault(); f[0].focus(); }
        }
      }
      d.addEventListener('keydown', onKey, true);
      ov.addEventListener('mousedown', function (e) { if (e.target === ov) close(inp ? null : false); });
      if (cancel) cancel.addEventListener('click', function () { close(inp ? null : false); });
      ok.addEventListener('click', accept);
      if (inp) inp.addEventListener('input', sync);
      sync();
      requestAnimationFrame(function () { ov.classList.add('in'); (inp || (tone === 'danger' && cancel) || ok).focus(); if (inp && !opts.input.match) inp.select(); });
    });
  }
  window.hpDialog = dialog;

  // confirm / prompt / type-to-confirm on forms: show our dialog first, then submit the form for real.
  d.addEventListener('submit', function (e) {
    var f = e.target, m;
    if (f.__hpOk) { f.__hpOk = false; lockButton(f); return; }
    var ask = null;
    if ((m = f.getAttribute('data-typeconfirm'))) {
      ask = dialog({ tone: 'danger', title: 'This cannot be undone', ok: 'Delete permanently',
        message: 'To confirm, type the name below exactly as shown.', input: { match: m, placeholder: m } })
        .then(function (v) { if (v === null) return false; var h = f.querySelector('input[name=confirm]'); if (h) h.value = v.trim(); return true; });
    } else if ((m = f.getAttribute('data-confirm'))) {
      var danger = /cannot be undone|delete|remove|reboot|stop/i.test(m);
      ask = dialog({ tone: danger ? 'danger' : 'ask', title: danger ? 'Are you sure?' : 'Please confirm', message: m, ok: danger ? 'Yes, continue' : 'Continue' });
    } else if ((m = f.getAttribute('data-prompt'))) {
      ask = dialog({ tone: 'ask', title: m, ok: 'Save', input: { value: f.getAttribute('data-default') || '', mono: true } })
        .then(function (r) {
          if (r === null || r === '') return false;
          var t = f.querySelector('input[name=' + f.getAttribute('data-field') + ']'); if (t) t.value = r; return true;
        });
    }
    if (!ask) { lockButton(f); return; }
    e.preventDefault();
    ask.then(function (go) { if (go) { f.__hpOk = true; if (f.requestSubmit) f.requestSubmit(); else { lockButton(f); f.submit(); } } });
  });
  function lockButton(f) { var b = f.querySelector('button:not(.g):not(.d)'); if (b && !f.hasAttribute('data-nolock')) setTimeout(function () { b.disabled = true; }, 0); }

  // live refresh for the Tasks page
  var rf = $('[data-refresh]'); if (rf) setTimeout(function () { location.reload(); }, parseInt(rf.getAttribute('data-refresh'), 10) || 3000);

  // file upload with progress (PUT streamed to the site user's worker)
  var up = $('#up'), st = $('#upstat');
  if (up) {
    up.addEventListener('change', function () {
      var files = Array.prototype.slice.call(up.files), i = 0, fail = 0;
      if (!files.length) return;
      (function next() {
        if (i >= files.length) { st.textContent = fail ? 'Done with ' + fail + ' error(s)' : 'Upload complete'; if (!fail) setTimeout(function () { location.reload(); }, 600); return; }
        var f = files[i++], x = new XMLHttpRequest();
        x.open('PUT', '/files/upload?site=' + encodeURIComponent(up.dataset.site) + '&p=' + encodeURIComponent(up.dataset.path) + '&name=' + encodeURIComponent(f.name));
        x.setRequestHeader('X-CSRF-Token', up.dataset.csrf);
        x.upload.onprogress = function (ev) { if (ev.lengthComputable) st.textContent = f.name + ' (' + i + '/' + files.length + '): ' + Math.round(ev.loaded / ev.total * 100) + '%'; };
        x.onload = function () { if (x.status !== 200) { fail++; var msg = 'failed'; try { msg = JSON.parse(x.responseText).error; } catch (e) {} dialog({ tone: 'warn', title: 'Upload failed', message: f.name + ': ' + msg, ok: 'OK', hideCancel: true }); } next(); };
        x.onerror = function () { fail++; dialog({ tone: 'warn', title: 'Upload failed', message: f.name + ': network error', ok: 'OK', hideCancel: true }); next(); };
        x.send(f);
      })();
    });
  }

  // generated password helper for forms with [data-gen]
  $$('[data-gen]').forEach(function (b) {
    b.addEventListener('click', function () {
      // 20 letters/digits (no look-alikes) - accepted by database, WordPress and client password rules
      var cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789', a = new Uint8Array(40), o = '', i = 0; crypto.getRandomValues(a);
      while (o.length < 20 && i < a.length) { if (a[i] < 232) o += cs[a[i] % cs.length]; i++; }
      var t = $(b.getAttribute('data-gen')); if (t) t.value = o;
    });
  });
})();
