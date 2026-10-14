(() => {
  const input = document.querySelector('input[name="f_asn"]');
  const list = document.getElementById('asn-suggestions');
  const arrow = document.getElementById('asn-show-suggestions');
  if (!input || !list || !arrow) return;
  const values = Array.from(list.options, option => option.value);
  let typed = input.value;
  const asnMode = value => /^AS/i.test(value);
  const updateMode = () => {
    if (asnMode(input.value)) input.removeAttribute('list');
    else input.setAttribute('list', list.id);
  };
  const showSuggestions = () => {
    if (input.selectionStart < input.selectionEnd && input.value.startsWith(typed)) {
      input.value = typed;
    }
    input.setAttribute('list', list.id);
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
    if (typeof input.showPicker === 'function') {
      try { input.showPicker(); return true; } catch (_) { /* Native list remains available. */ }
    }
    return false;
  };
  input.addEventListener('input', event => {
    typed = input.value;
    updateMode();
    if (event.isComposing || !/^AS\d*$/i.test(typed) ||
        (event.inputType || '').startsWith('delete') || input.selectionStart !== typed.length) return;
    const match = values.find(value => value.toLowerCase().startsWith(typed.toLowerCase()));
    const number = match && /^AS\d+/i.exec(match);
    if (!number || number[0].length === typed.length) return;
    input.value = number[0];
    input.setSelectionRange(typed.length, number[0].length);
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown') {
      if (showSuggestions()) event.preventDefault();
    } else if (event.key === 'Escape' && input.selectionStart < input.selectionEnd) {
      input.value = typed;
      input.setSelectionRange(typed.length, typed.length);
      updateMode();
      event.preventDefault();
    } else if (['ArrowRight', 'End', 'Tab', 'Enter'].includes(event.key) &&
               input.selectionStart < input.selectionEnd) {
      input.setSelectionRange(input.value.length, input.value.length);
      typed = input.value;
    }
  });
  arrow.addEventListener('click', showSuggestions);
  arrow.hidden = false;
  updateMode();
})();
