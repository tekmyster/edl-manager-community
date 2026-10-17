/* Same details for pointer and keyboard; no chart dependency or remote assets. */
document.querySelectorAll('[data-chart]').forEach(chart => {
  const details = chart.querySelector('.ops-hover');
  chart.querySelectorAll('[data-tip]').forEach(point => {
    const show = () => { details.textContent = point.dataset.tip; };
    point.addEventListener('focus', show);
    point.addEventListener('mouseenter', show);
  });
});
