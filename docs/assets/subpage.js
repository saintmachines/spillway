// Product navigation shared by the results and integration pages.
(function () {
  'use strict';
  var root = document.documentElement;
  var theme = document.getElementById('themeBtn');
  function chrome() {
    if (!root.getAttribute('data-theme')) return;
    var bg = getComputedStyle(root).getPropertyValue('--bg').trim();
    document.querySelectorAll('meta[name="theme-color"]').forEach(function (m) { m.setAttribute('content', bg); });
  }
  if (theme) theme.addEventListener('click', function () {
    var current = root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    var next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('spw-theme', next); } catch (e) {}
    chrome();
  });
  chrome();
  var button = document.getElementById('menuBtn'), panel = document.getElementById('menuPanel');
  if (button && panel) {
    var start = 0, eat = false, first = panel.querySelector('a');
    function close() { panel.hidden = true; button.setAttribute('aria-expanded', 'false'); }
    // The panel comes after the header row in the page, so Tab from the open button goes to its first link, and back.
    button.addEventListener('keydown', function (e) { if (e.key === 'Tab' && !e.shiftKey && !panel.hidden && first) { e.preventDefault(); first.focus(); } });
    panel.addEventListener('keydown', function (e) { if (e.key === 'Tab' && e.shiftKey && e.target === first) { e.preventDefault(); button.focus(); } });
    button.addEventListener('click', function () {
      panel.hidden = !panel.hidden;
      button.setAttribute('aria-expanded', String(!panel.hidden));
      start = scrollY;
    });
    panel.addEventListener('click', function (e) { if (e.target.closest('a')) close(); });
    document.addEventListener('keydown', function (e) {
      eat = false;
      if (e.key === 'Escape' && !panel.hidden) { close(); button.focus({preventScroll: true}); }
    });
    document.addEventListener('pointerdown', function (e) {
      var outside = !panel.hidden && !panel.parentNode.contains(e.target);
      eat = outside && e.button === 0;
      if (outside) close();
    });
    document.addEventListener('pointercancel', function () { eat = false; });
    document.addEventListener('click', function (e) {
      if (eat) { eat = false; e.preventDefault(); e.stopPropagation(); }
    }, true);
    addEventListener('scroll', function () { if (!panel.hidden && Math.abs(scrollY - start) > 48) close(); }, {passive: true});
  }
  document.querySelectorAll('[data-copy]').forEach(function (button) {
    button.addEventListener('click', function () {
      var source = document.querySelector(button.getAttribute('data-copy'));
      if (!source) return;
      var text = source.textContent;
      function done() {
        var label = button.textContent, status = document.getElementById('copy-status');
        button.textContent = 'Copied';
        if (status) status.textContent = 'Copied to the clipboard';
        setTimeout(function () { button.textContent = label; if (status) status.textContent = ''; }, 1400);
      }
      function select() { var range = document.createRange(); range.selectNodeContents(source); var selected = getSelection(); selected.removeAllRanges(); selected.addRange(range); }
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, select);
      else select();
    });
  });
})();
