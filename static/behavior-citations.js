/* Reveal cited rows and move focus without changing saved data or form state. */
(() => {
  function reveal(hash, focus) {
    if (!/^#(?:behavior-|case-current-)/.test(hash)) return;
    const row = document.getElementById(hash.slice(1));
    if (!row) return;
    for (let parent = row.parentElement; parent; parent = parent.parentElement) {
      if (parent.tagName === 'DETAILS') parent.open = true;
    }
    if (focus) requestAnimationFrame(() => {
      row.focus({preventScroll: true});
      row.scrollIntoView({block: 'center'});
    });
  }
  document.addEventListener('click', event => {
    const link = event.target.closest('a[data-behavior-citation]');
    if (link && link.hash) reveal(link.hash, true);
  });
  window.addEventListener('hashchange', () => reveal(location.hash, true));
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => reveal(location.hash, true));
  else reveal(location.hash, true);
})();
