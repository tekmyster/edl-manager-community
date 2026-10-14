(() => {
 const dialog=document.getElementById('metric-dialog'), panel=document.getElementById('metric-results');
 if(!dialog || !dialog.showModal) return;
 let controller, opener, busy=false, revision=0, timer;
 async function load(url) {
  const id=++revision;if(controller) controller.abort(); controller=new AbortController(); busy=true;
  panel.setAttribute('aria-busy','true');panel.replaceChildren();
  const loading=document.createElement('div');loading.className='table-loading';loading.setAttribute('role','status');
  const spinner=document.createElement('span');spinner.className='request-spinner';spinner.setAttribute('aria-hidden','true');loading.append(spinner,document.createTextNode('Loading results…'));panel.append(loading);
  try {
   const response=await fetch(url,{credentials:'same-origin',headers:{'X-EDL-Modal':'1'},signal:controller.signal});
   if(!response.ok || response.redirected) throw Error();
   const html=await response.text();if(id!==revision)return;
   panel.innerHTML=html; document.getElementById('metric-title').textContent=panel.querySelector('[data-results-title]').dataset.resultsTitle;
  } catch(error) { if(id===revision && error.name!=='AbortError'){panel.textContent='Unable to load results. ';const retry=document.createElement('button');retry.textContent='Retry';retry.addEventListener('click',()=>load(url));panel.append(retry);} }
  finally {if(id===revision){busy=false;panel.removeAttribute('aria-busy');}}
 }
 document.addEventListener('click',event=>{
  const tile=event.target.closest('[data-results-modal]');
  if(!tile || event.button!==0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  event.preventDefault(); opener=tile; document.getElementById('metric-title').textContent=tile.querySelector('span').textContent;dialog.showModal();load(tile.href);
 },true);
 dialog.querySelector('[data-close-modal]').addEventListener('click',()=>dialog.close());
 dialog.addEventListener('close',()=>{revision++;clearTimeout(timer);if(controller) controller.abort();if(opener) opener.focus();});
 dialog.addEventListener('click',event=>{if(event.target===dialog) dialog.close();});
 panel.addEventListener('click',event=>{const link=event.target.closest('a');if(!link || !new URL(link.href).pathname.startsWith('/results/') || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;event.preventDefault();load(link.href);});
 panel.addEventListener('submit',event=>{if(event.target.method.toLowerCase()!=='get')return;event.preventDefault();if(busy)return;const url=new URL(event.target.action);url.search=new URLSearchParams(new FormData(event.target)).toString();load(url);});
})();
