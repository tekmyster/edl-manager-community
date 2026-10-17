/* Shared pointer/keyboard interval details; no persistent explanatory copy. */
document.querySelectorAll('[data-chart]').forEach(chart => {
  const details = chart.querySelector('.ops-hover');
  if (!details) return;
  const clear = () => {
    const focused = chart.querySelector('[data-tip]:focus');
    details.textContent = focused ? focused.dataset.tip : '';
  };
  chart.querySelectorAll('[data-tip]').forEach(point => {
    const show = () => { details.textContent = point.dataset.tip; };
    point.addEventListener('focus', show);
    point.addEventListener('mouseenter', show);
    point.addEventListener('mouseleave', clear);
    point.addEventListener('blur', () => { details.textContent = ''; });
  });
  chart.addEventListener('mouseleave', clear);
});
