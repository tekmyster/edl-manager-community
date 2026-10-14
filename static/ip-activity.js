(() => {
  const panel = document.getElementById('activity');
  if (!panel) return;
  let attempts = 0;
  async function poll() {
    if (panel.querySelector('[data-activity-loading="true"]') === null || attempts++ >= 30) return;
    try {
      const response = await fetch(panel.dataset.activityUrl, {credentials: 'same-origin', headers: {'Accept': 'text/html'}});
      if (!response.ok || response.redirected) return;
      const content = await response.text();
      // Never replace filters while the administrator is editing them.
      if (!panel.contains(document.activeElement)) panel.innerHTML = content;
    } catch (_) { /* Keep the existing source evidence visible. */ }
    window.setTimeout(poll, 2000);
  }
  window.setTimeout(poll, 2000);
})();
