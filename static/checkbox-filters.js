(() => {
  const filters = [...document.querySelectorAll('.checkbox-filter')];
  function update(filter) {
    const count = filter.querySelectorAll('input[type="checkbox"]:checked').length;
    filter.querySelector('[data-filter-summary]').textContent = count ? `${count} selected` : 'All sources';
  }
  filters.forEach(filter => {
    const clear = filter.querySelector('[data-clear-filter]');
    clear.hidden = false;
    filter.addEventListener('change', () => update(filter));
    filter.addEventListener('toggle', () => {
      if (!filter.open) return;
      const panel=filter.querySelector('.checkbox-filter-panel'), box=filter.querySelector('summary').getBoundingClientRect();
      panel.style.position='fixed';panel.style.top=`${box.bottom+5}px`;panel.style.left=`${Math.max(8,Math.min(box.left,innerWidth-320))}px`;
      panel.style.minWidth=`${box.width}px`;panel.style.maxHeight=`${Math.max(90,innerHeight-box.bottom-20)}px`;
    });
    clear.addEventListener('click', () => {
      filter.querySelectorAll('input[type="checkbox"]').forEach(box => { box.checked = false; });
      update(filter);
      filter.querySelector('input[type="checkbox"]')?.dispatchEvent(new Event('change',{bubbles:true}));
    });
    update(filter);
  });
  document.addEventListener('click', event => {
    filters.forEach(filter => { if (!filter.contains(event.target)) filter.open = false; });
  });
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    filters.forEach(filter => {
      if (!filter.open) return;
      const focused = filter.contains(document.activeElement);
      filter.open = false;
      if (focused) filter.querySelector('summary').focus();
    });
  });
  window.addEventListener('pageshow', () => filters.forEach(update));
})();
