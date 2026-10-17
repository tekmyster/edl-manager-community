(() => {
  const mode = document.querySelector('select[name="daily_budget_mode"]');
  const limit = document.querySelector('input[name="daily_budget"]');
  if (!mode || !limit) return;
  const update = () => {
    limit.disabled = mode.value === 'unlimited';
    limit.required = !limit.disabled;
  };
  mode.addEventListener('change', update);
  update();
})();
