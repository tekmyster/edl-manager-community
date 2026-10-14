(() => {
  const overlay = document.getElementById('request-progress');
  const message = document.getElementById('request-progress-message');
  if (!overlay || !message) return;
  let pending = false;
  let timers = [];
  const controls = new Map();
  function reset() {
    pending = false;
    timers.forEach(clearTimeout);
    timers = [];
    overlay.hidden = true;
    document.body.removeAttribute('aria-busy');
    for (const [control, original] of controls) {
      if (original === null) control.removeAttribute('aria-disabled');
      else control.setAttribute('aria-disabled', original);
    }
    controls.clear();
  }
  function start(text) {
    pending = true;
    message.textContent = text;
    overlay.hidden = false;
    document.body.setAttribute('aria-busy', 'true');
    // Keep form fields enabled so native submission includes their values.
    document.querySelectorAll('button[type="submit"],button:not([type]),input[type="submit"]').forEach(control => {
      controls.set(control, control.getAttribute('aria-disabled'));
      control.setAttribute('aria-disabled', 'true');
    });
    timers.push(setTimeout(() => { message.textContent = 'Still working. Please wait…'; }, 8000));
    timers.push(setTimeout(() => { message.textContent = 'This is taking longer than usual. Please keep this page open.'; }, 30000));
  }
  document.addEventListener('submit', event => {
    if (event.defaultPrevented) return;
    if (pending) { event.preventDefault(); return; }
    const form = event.target;
    const action = new URL(form.action, location.href);
    const messages = {'/login': 'Signing in…', '/logout': 'Signing out…', '/build': 'Building lists…', '/settings': 'Saving settings…', '/password': 'Changing password…', '/providers': 'Saving provider keys…', '/rules': 'Saving rule…'};
    start(form.method.toLowerCase() === 'get' ? 'Loading results…' : messages[action.pathname] || 'Working…');
  });
  document.addEventListener('click', event => {
    if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const link = event.target.closest('a[href]');
    if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
    const destination = new URL(link.href, location.href);
    const current = new URL(location.href);
    if (destination.origin !== current.origin || destination.protocol !== current.protocol || destination.pathname.startsWith('/lists/')) return;
    if (destination.pathname === current.pathname && destination.search === current.search) return;
    if (pending) { event.preventDefault(); return; }
    start('Loading page…');
  });
  // Restore controls when returning through browser Back/Forward, including bfcache.
  window.addEventListener('pageshow', reset);
})();
