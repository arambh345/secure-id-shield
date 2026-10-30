// Backend seam. All network code lives here; the rest of the UI never calls fetch.
const mins=t=>Math.max(0,Math.round((Date.now()-new Date(t))/6e4));
// Backend JSON (readable names) -> the short field names the UI uses. Edit these if your fields differ.
const MAP={alert:b=>({id:b.id,t:b.title,sev:b.severity,cat:b.category,u:b.user,ip:b.ip,ago:mins(b.createdAt),st:b.status}),
user:b=>({n:b.name,e:b.email,r:b.role,mfa:b.mfa,risk:b.risk,seen:mins(b.lastSeen),lock:b.locked}),
log:b=>({m:mins(b.at),u:b.user,ev:b.event,k:b.kind,ip:b.ip,loc:b.location,risk:b.risk}),
key:b=>({n:b.name,a:b.algorithm,b:b.bits,d:Math.floor(mins(b.rotatedAt)/1440)}),
session:b=>({u:b.user,dev:b.device,ip:b.ip,loc:b.location,m:mins(b.startedAt)})};
const API={live:CONFIG.SOURCE==='http',
async req(m,p,b){const h={'Content-Type':'application/json'};if(CONFIG.getToken)h.Authorization='Bearer '+await CONFIG.getToken();
const r=await fetch(CONFIG.BASE_URL+p,{method:m,headers:h,body:b?JSON.stringify(b):undefined});if(!r.ok)throw new Error(m+' '+p+' '+r.status);return r.json()},
send(m,p,b){if(!API.live)return;API.req(m,p,b).catch(e=>{console.error(e);toast('Backend error: change not saved')})},
async boot(){if(!API.live)return null;const g=x=>API.req('GET','/api/'+x),[al,us,lg,ky,se,ov]=await Promise.all(['alerts','users','logs','keys','sessions','overview'].map(g));
const o={al:al.map(MAP.alert),us:us.map(MAP.user),lg:lg.map(MAP.log),ky:ky.map(MAP.key),se:se.map(MAP.session),tr:ov.riskTrend};
return Object.fromEntries(Object.entries(o).filter(([,v])=>v))},
subscribe(cb){if(!API.live)return;const M={alert:MAP.alert,log:MAP.log,risk:x=>x},es=new EventSource(CONFIG.BASE_URL+'/api/stream');
es.onmessage=e=>{const m=JSON.parse(e.data);if(M[m.type])cb({type:m.type,data:M[m.type](m.data)})}},
updateAlert:(id,p)=>API.send('PATCH','/api/alerts/'+id,p),
updateUser:(e,p)=>API.send('PATCH','/api/users/'+encodeURIComponent(e),p),
rotateKey:n=>API.send('POST','/api/keys/rotate',{name:n}),
revokeSession:s=>API.send('POST','/api/sessions/revoke',{user:s.u,device:s.dev}),
saveSetting:(k,v)=>API.send('PUT','/api/settings/'+k,v),
saveScan:r=>API.send('POST','/api/scans',{input:r.s,score:r.sc,verdict:r.v,findings:r.f.map(x=>x[1])})};
