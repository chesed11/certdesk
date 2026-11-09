const $ = s => document.querySelector(s);
let certificates = [], events = [], editId = null;
const labels = {expired:'已过期',critical:'紧急',warning:'需关注',healthy:'正常'};
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('show');clearTimeout(toast.timer);toast.timer=setTimeout(()=>el.classList.remove('show'),3500)}
async function api(path, options={}){const response=await fetch(path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});let data;try{data=await response.json()}catch{throw Error('服务器响应异常')}if(response.status===401){showLogin();throw Error('请先登录')}if(!response.ok)throw Error(data.error||'请求失败');return data}
async function refresh(){try{const [overview,certs,history]=await Promise.all([api('/api/overview'),api('/api/certificates'),api('/api/events')]);certificates=certs;events=history;for(const key of ['total','expired','critical','warning'])$('#'+key).textContent=overview[key];$('#updated').textContent='◷ 更新于 '+new Date().toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});renderCerts();renderEvents()}catch(e){toast('加载失败：'+e.message);$('#count').textContent='加载失败，请确认本地服务正在运行。'}}
function renderCerts(){const query=$('#search').value.trim().toLowerCase(),filter=$('#filter').value;const rows=certificates.filter(c=>(!filter||c.status===filter)&&[c.name,c.domain,c.owner,c.issuer,c.location].some(v=>String(v||'').toLowerCase().includes(query)));$('#certRows').innerHTML=rows.length?rows.map(c=>`<tr><td><strong>${esc(c.name)}</strong><small>${esc(c.domain)}</small></td><td><span class="status ${esc(c.status)}">● ${esc(labels[c.status]||c.status)}</span></td><td><strong>${esc(c.expires_on)}</strong><small>${c.days_remaining<0?'已过期 '+Math.abs(c.days_remaining)+' 天':c.days_remaining===0?'今天到期':'剩余 '+c.days_remaining+' 天'}</small></td><td>${esc(c.owner||'—')}</td><td>${esc(c.environment||'—')}</td><td><button class="action" data-edit="${c.id}">编辑</button><button class="action" data-event="${c.id}">记录</button><button class="action danger" data-delete="${c.id}">删除</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">暂无符合条件的证书</td></tr>';$('#count').textContent=`显示 ${rows.length} 项，共 ${certificates.length} 项`;}
function renderEvents(){const recent=events.slice(0,6);$('#eventList').innerHTML=recent.length?recent.map(e=>`<div class="event"><div class="event-icon">↻</div><div class="event-body"><div class="event-title">${esc(e.event_type)} · ${esc(e.certificate_name)}</div><div class="event-note">${esc(e.notes)}</div></div><div class="event-date">${esc(new Date(e.created_at).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}))}</div></div>`).join(''):'<div class="empty">暂无操作记录</div>';}
function openCert(id){const form=$('#certForm');form.reset();editId=id||null;$('#formTitle').textContent=id?'编辑证书':'添加证书';if(id){const c=certificates.find(x=>x.id===id);if(!c)return;for(const key of ['name','domain','issuer','expires_on','owner','environment','location','notes'])form.elements[key].value=c[key]||''}$('#certDialog').showModal()}
function openEvent(id){if(!certificates.length)return toast('请先添加证书');const form=$('#eventForm');form.reset();$('#eventCert').innerHTML=certificates.map(c=>`<option value="${c.id}">${esc(c.name)} · ${esc(c.domain)}</option>`).join('');if(id)$('#eventCert').value=String(id);$('#eventDialog').showModal()}
$('#addBtn').onclick=()=>openCert();$('#eventBtn').onclick=()=>openEvent();$('#search').oninput=renderCerts;$('#filter').onchange=renderCerts;
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>document.getElementById(b.dataset.close).close());
$('#certRows').addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.edit)openCert(Number(b.dataset.edit));if(b.dataset.event)openEvent(Number(b.dataset.event));if(b.dataset.delete){const c=certificates.find(x=>x.id===Number(b.dataset.delete));if(!confirm(`确定删除“${c?.name||''}”及其关联记录吗？`))return;try{await api('/api/certificates/'+b.dataset.delete,{method:'DELETE'});toast('证书已删除');await refresh()}catch(err){toast('删除失败：'+err.message)}}});
$('#certForm').onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.currentTarget));try{await api('/api/certificates'+(editId?'/'+editId:''),{method:editId?'PUT':'POST',body:JSON.stringify(data)});$('#certDialog').close();toast('证书已保存');await refresh()}catch(err){toast('保存失败：'+err.message)}};
$('#eventForm').onsubmit=async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.currentTarget));data.certificate_id=Number(data.certificate_id);try{await api('/api/events',{method:'POST',body:JSON.stringify(data)});$('#eventDialog').close();toast('记录已保存');await refresh()}catch(err){toast('保存失败：'+err.message)}};
document.querySelectorAll('.nav').forEach(a=>a.addEventListener('click',()=>{document.querySelectorAll('.nav').forEach(x=>x.classList.remove('active'));a.classList.add('active')}));
function showLogin(){if(!$('#loginDialog').open)$('#loginDialog').showModal()}
$('#loginDialog').addEventListener('cancel',e=>e.preventDefault());
$('#loginForm').onsubmit=async e=>{e.preventDefault();const error=$('#loginError');error.textContent='';try{const response=await fetch('/api/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:e.currentTarget.elements.token.value})});if(!response.ok)throw Error('访问码无效');e.currentTarget.reset();$('#loginDialog').close();await Promise.all([refresh(),loadAutomation(true)]);}catch(err){error.textContent=err.message}};

// Inspection settings are independent of the root-owned renewal policy.
const autoForm = $('#autoForm');
let autoBusy = false;
function markBusy(value){autoBusy=value;autoForm.querySelector('button[type="submit"]').disabled=value}
async function loadAutomation(fill=false){
 try{
   const state=await api('/api/system-status');
   const labels={verified:'已验证',no_change:'证书未变更',unverified:'待确认',failed:'失败',timeout:'超时'};
   $('#autoState').textContent=labels[state.status]||'未配置或无记录';
   $('#autoState').className='status '+(state.status==='verified'||state.status==='no_change'?'healthy':'warning');
   $('#autoSummary').textContent=(state.updated_at?state.updated_at+' · ':'')+(state.summary||'尚无可信的系统执行报告，请检查部署和系统日志。');
 }catch(err){$('#autoState').textContent='连接失败';$('#autoSummary').textContent='读取失败：'+err.message}
}
autoForm.onsubmit=async e=>{e.preventDefault();if(autoBusy)return;markBusy(true);$('#tlsResult').textContent='检测中…';try{const r=await api('/api/automation/check',{method:'POST',body:JSON.stringify({domain:autoForm.elements.domain.value.trim()})});$('#tlsResult').textContent=(r.ok?'验证通过：':'验证失败：')+(r.message||'')+(r.expires_at?'；到期：'+r.expires_at:'')}catch(err){$('#tlsResult').textContent='检测失败：'+err.message}finally{markBusy(false)}};
refresh();loadAutomation(true);setInterval(()=>{if(!$('#loginDialog').open)loadAutomation()},10000);
