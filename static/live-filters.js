(() => {
 const section=document.getElementById('ip-evidence'), form=document.getElementById('evidence-filters');
 if(!section || !form)return;
 const status=document.createElement('p');status.className='filter-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');form.append(status);
 const loading=document.createElement('div');loading.className='table-loading';loading.hidden=true;loading.setAttribute('aria-hidden','true');
 const spinner=document.createElement('span');spinner.className='request-spinner';loading.append(spinner,document.createTextNode('Loading results…'));section.querySelector('.scroll').prepend(loading);
 function busy(value){
  loading.hidden=!value;
  section.querySelector('tbody').inert=value;
  section.querySelectorAll('.pagination').forEach(page=>{page.inert=value;});
  section.querySelectorAll('thead th > a').forEach(link=>{if(value)link.setAttribute('aria-disabled','true');else link.removeAttribute('aria-disabled');});
 }
 let timer,controller,revision=0;
 function urlForFilters(){const url=new URL(form.action,location.href);url.search=new URLSearchParams(new FormData(form)).toString();url.searchParams.delete('page');return url;}
 function invalidate(){clearTimeout(timer);revision++;if(controller)controller.abort();section.setAttribute('aria-busy','true');busy(true);section.dispatchEvent(new Event('edl:filter-pending'));status.textContent='Updating results…';return revision;}
 async function load(url,id){
  controller=new AbortController();
  try{
   const response=await fetch(url,{credentials:'same-origin',signal:controller.signal});
   if(response.redirected || !response.ok)throw Error();
   const html=await response.text();if(id!==revision)return;
   const next=new DOMParser().parseFromString(html,'text/html').getElementById('ip-evidence');
   if(!next || !next.querySelector('tbody'))throw Error();
   // Keep the controls in place: typing focus, ASN completion and open checkbox menus survive.
   section.querySelector('tbody').replaceWith(next.querySelector('tbody'));
   const oldPages=section.querySelectorAll('.pagination'),newPages=next.querySelectorAll('.pagination');
   oldPages.forEach((page,i)=>page.replaceWith(newPages[i]));
   const heads=section.querySelectorAll('thead th'),newHeads=next.querySelectorAll('thead th');
   heads.forEach((head,i)=>{const link=head.querySelector('a');if(link){const fresh=newHeads[i].querySelector('a');link.href=fresh.href;link.textContent=fresh.textContent;head.setAttribute('aria-sort',newHeads[i].getAttribute('aria-sort'));}});
   for(const name of ['sort','direction'])form.elements.namedItem(name).value=next.querySelector(`#evidence-filters input[name="${name}"]`).value;
   // Update saved-layout return state without submitting a stale query later.
   section.querySelector('.column-chooser [name="return_query"]').value=url.search.slice(1);
   history.replaceState(null,'',url);section.dispatchEvent(new Event('edl:rows-updated'));
   status.textContent=section.querySelector('.pagination > span').textContent;
  }catch(error){if(id===revision && error.name!=='AbortError')status.textContent='Unable to update results. Showing previous results; use Apply filters to retry.';}
  finally{if(id===revision){section.removeAttribute('aria-busy');busy(false);section.dispatchEvent(new Event('edl:filter-complete'));}}
 }
 function schedule(delay){const id=invalidate();timer=setTimeout(()=>load(urlForFilters(),id),delay);}
 section.addEventListener('input',event=>{if(event.target.form===form && !['checkbox','hidden'].includes(event.target.type) && event.target.tagName!=='SELECT' && !event.isComposing)schedule(400);});
 section.addEventListener('compositionend',event=>{if(event.target.form===form)schedule(400);});
 section.addEventListener('change',event=>{if(event.target.form===form)schedule(0);});
 // Capture before the site's full-page progress handler; native GET remains the no-JS fallback.
 section.addEventListener('submit',event=>{
  if(section.getAttribute('aria-busy')==='true' && event.target.matches('.page-jump,#bulk-whitelist')){event.preventDefault();return;}
  if(event.target===form || event.target.matches('.page-jump')){event.preventDefault();const url=urlForFilters();if(event.target!==form){if(!event.target.checkValidity())return;url.searchParams.set('page',event.target.elements.namedItem('page').value);}load(url,invalidate());}
 },true);
 section.addEventListener('click',event=>{
  if(section.getAttribute('aria-busy')==='true' && event.target.closest('tbody,.pagination,thead th > a,[data-select-page]')){event.preventDefault();event.stopImmediatePropagation();return;}
  const link=event.target.closest('a');if(!link || event.button!==0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey)return;
  if(!link.closest('thead,.pagination') && !(link.closest('.filter-actions') && link.textContent.trim()==='Reset filters'))return;
  // Reset needs to reset the controls too, so use the existing normal navigation.
  if(link.textContent.trim()==='Reset filters')return;
  event.preventDefault();const url=urlForFilters(),target=new URL(link.href);
  for(const name of ['sort','direction','page'])if(target.searchParams.has(name))url.searchParams.set(name,target.searchParams.get(name));
  load(url,invalidate());
 },true);
})();
