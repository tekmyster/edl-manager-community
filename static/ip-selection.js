(() => {
 const form=document.getElementById('bulk-whitelist'), section=document.getElementById('ip-evidence');
 if(!form || !section) return;
 let boxes=[...section.querySelectorAll('[data-ip-selection]')];const all=section.querySelector('[data-select-page]'), clear=form.querySelector('[data-clear-selection]'), submit=form.querySelector('button:not([type])');
 let anchor=null;
 function update(){
  const selected=boxes.filter(box=>box.checked);
  const editor=section.querySelector('.bulk-editor'),label=section.querySelector('[data-selection-label]');
  if(label)label.textContent=selected.length?`Whitelist ${selected.length} selected ${selected.length===1?'address':'addresses'}`:'Whitelist selected addresses';
  if(editor && selected.length)editor.open=true;
  form.querySelector('[data-selection-count]').textContent=`${selected.length} selected`;
  form.querySelector('[data-selected-addresses]').textContent=selected.map(box=>box.value).join(', ') || 'None';
  submit.disabled=!selected.length || section.getAttribute('aria-busy')==='true';
  boxes.forEach(box=>box.closest('tr').classList.toggle('is-selected',box.checked));
  all.checked=boxes.length>0 && selected.length===boxes.length;all.indeterminate=selected.length>0 && selected.length<boxes.length;all.disabled=!boxes.length || section.getAttribute('aria-busy')==='true';
 }
 function range(index,checked){const start=anchor===null?index:anchor;for(let i=Math.min(start,index);i<=Math.max(start,index);i++)boxes[i].checked=checked;}
 section.addEventListener('click',event=>{
  const row=event.target.closest('[data-select-ip]');if(!row)return;
  const box=row.querySelector('[data-ip-selection]'), index=boxes.indexOf(box);
  if(event.target===box){if(event.shiftKey)range(index,box.checked);else anchor=index;update();return;}
  if(event.target.closest('a,button,input,select,textarea,label,summary,details'))return;
  event.preventDefault();
  if(event.shiftKey)range(index,true);
  else if(event.ctrlKey || event.metaKey){box.checked=!box.checked;anchor=index;}
  else {boxes.forEach(item=>item.checked=false);box.checked=true;anchor=index;}
  update();
 });
 section.addEventListener('change',event=>{if(event.target.matches('[data-ip-selection]'))update();});
 all.addEventListener('change',()=>{boxes.forEach(box=>box.checked=all.checked);anchor=null;update();});
 clear.hidden=false;clear.addEventListener('click',()=>{boxes.forEach(box=>box.checked=false);anchor=null;update();});
 form.addEventListener('submit',event=>{if(section.getAttribute('aria-busy')==='true'){event.preventDefault();return;}if(!boxes.some(box=>box.checked)){event.preventDefault();form.querySelector('[data-selection-count]').textContent='Select at least one address.';}});
 section.addEventListener('edl:rows-updated',()=>{boxes=[...section.querySelectorAll('[data-ip-selection]')];anchor=null;update();});
 section.addEventListener('edl:filter-pending',update);section.addEventListener('edl:filter-complete',update);
 window.addEventListener('pageshow',update);update();
})();