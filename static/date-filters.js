(() => {
 function update(filter){
  const fields=filter.querySelectorAll('input[type="date"]');
  if(fields.length!==3)return;
  const [day,start,end]=fields;
  end.min=start.value;start.max=end.value;
  filter.querySelector('summary').firstChild.textContent=day.value || (start.value||end.value ? `${start.value||'Any'} – ${end.value||'Any'} ` : 'Any date ');
 }
 function place(filter){
  if(!filter.open)return;
  const panel=filter.querySelector('.date-filter-panel'),scroll=filter.closest('.scroll');
  const rect=filter.getBoundingClientRect(),bounds=scroll?scroll.getBoundingClientRect():{left:0,right:innerWidth};
  const left=Math.max(0,bounds.left),right=Math.min(innerWidth,bounds.right);
  panel.style.maxWidth=`${Math.max(150,right-left-8)}px`;
  panel.style.left=`${Math.max(left-rect.left,Math.min(0,right-rect.left-panel.offsetWidth-4))}px`;
 }
 document.querySelectorAll('.date-filter').forEach(update);
 document.addEventListener('toggle',event=>{if(event.target.matches('.date-filter'))place(event.target);},true);
 window.addEventListener('resize',()=>document.querySelectorAll('.date-filter[open]').forEach(place));
 document.addEventListener('change',event=>{
  const filter=event.target.closest('.date-filter');if(!filter)return;
  const fields=filter.querySelectorAll('input[type="date"]');
  if(event.target===fields[0] && event.target.value){fields[1].value='';fields[2].value='';}
  else if(event.target.value)fields[0].value='';
  update(filter);
 },true);
 document.addEventListener('click',event=>{
  if(event.target.matches('.date-filter input[type="date"]') && event.target.showPicker){try{event.target.showPicker();}catch(_) {}}
 });
})();
