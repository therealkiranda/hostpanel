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

  // confirm / prompt / type-to-confirm on forms
  d.addEventListener('submit', function (e) {
    var f = e.target, m;
    if ((m = f.getAttribute('data-typeconfirm'))) {
      var v = prompt('This cannot be undone.\n\nType  ' + m + '  to confirm:');
      if (v === null) { e.preventDefault(); return; }
      if (v.trim() !== m) { e.preventDefault(); alert('That did not match. Nothing was changed.'); return; }
      var h = f.querySelector('input[name=confirm]'); if (h) h.value = v.trim();
    }
    if ((m = f.getAttribute('data-confirm')) && !confirm(m)) { e.preventDefault(); return; }
    if ((m = f.getAttribute('data-prompt'))) {
      var r = prompt(m, f.getAttribute('data-default') || '');
      if (r === null || r === '') { e.preventDefault(); return; }
      var t = f.querySelector('input[name=' + f.getAttribute('data-field') + ']'); if (t) t.value = r;
    }
    var b = f.querySelector('button:not(.g):not(.d)'); if (b && !f.hasAttribute('data-nolock')) setTimeout(function () { b.disabled = true; }, 0);
  });

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
        x.onload = function () { if (x.status !== 200) { fail++; var msg = 'failed'; try { msg = JSON.parse(x.responseText).error; } catch (e) {} alert(f.name + ': ' + msg); } next(); };
        x.onerror = function () { fail++; alert(f.name + ': network error'); next(); };
        x.send(f);
      })();
    });
  }

  // generated password helper for forms with [data-gen]
  $$('[data-gen]').forEach(function (b) {
    b.addEventListener('click', function () {
      var a = new Uint8Array(12); crypto.getRandomValues(a);
      var t = $(b.getAttribute('data-gen')); if (t) t.value = Array.prototype.map.call(a, function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
    });
  });
})();
