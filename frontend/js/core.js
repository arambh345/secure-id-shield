const $=s=>document.querySelector(s),H=document.documentElement;
let seed=11;const rnd=()=>(seed=seed*16807%2147483647)/2147483647,ri=(a,b)=>a+Math.floor(rnd()*(b-a+1)),pk=a=>a[ri(0,a.length-1)];
const ev=s=>String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'),ago=m=>m<1?'just now':m<60?m+'m ago':Math.floor(m/60)+'h ago';
const REAL=['Aarav Mehta','Ishita Rao','Kabir Singh','Meera Nair','Rohan Gupta','Sana Khan','Vikram Joshi','Tanvi Shah','Arjun Das','Neha Verma','Dev Malhotra','Pooja Iyer'];const US=REAL.map((_,i)=>{const n=['Falcon','Maple','Cedar','Ember','Quartz','Willow','Cobalt','Raven','Aspen','Onyx','Saffron','Delta'][i]+'-'+ri(1000,9999);return({n,e:n.toLowerCase()+'@masked',r:pk(['Admin','Analyst','Engineer','Finance','HR','Viewer']),mfa:rnd()>.25,risk:ri(6,94),seen:ri(1,300),lock:false})});
const PR=1000003,md=a=>((a%PR)+PR)%PR,inv=a=>{let r=1,b=md(a),e=PR-2;while(e){if(e&1)r=r*b%PR;b=b*b%PR;e=Math.floor(e/2)}return r};
const split=s=>{const k=[ri(1,PR-1),ri(1,PR-1)];return [1,2,3,4,5].map(x=>[x,(s+k[0]*x+k[1]*x*x)%PR])};
const rec=sh=>sh.reduce((a,[xi,yi])=>{let n=1,d=1;sh.forEach(([xj])=>{if(xj!=xi){n=n*(PR-xj)%PR;d=d*md(xi-xj)%PR}});return(a+yi*n%PR*inv(d))%PR},0);
const DIR=US.map((u,i)=>{const emp=ri(100000,999999);return{u:u.n,real:REAL[i],emp,sh:split(emp)}});
const mp=(b,e,m)=>{let r=1;b%=m;while(e>0){if(e&1)r=r*b%m;b=b*b%m;e=Math.floor(e/2)}return r};
const bb84=eve=>{const N=32,R=()=>rnd()<.5?1:0,A_=Array.from({length:N},R),AB=A_.map(R),BB=A_.map(R),EB=A_.map(R);
const B=A_.map((a,i)=>{let bit=a,b=AB[i];if(eve){bit=EB[i]==AB[i]?a:R();b=EB[i]}return BB[i]==b?bit:R()});
const K=A_.map((_,i)=>AB[i]==BB[i]),sk=K.reduce((n,k)=>n+k,0),er=K.reduce((n,k,i)=>n+(k&&A_[i]!=B[i]),0);return{A_,AB,BB,B,K,q:sk?er/sk:0,sk}};
const AT=[['Impossible travel login','crit','Identity'],['Credential stuffing burst','crit','Identity'],['Phishing link clicked','high','Phishing'],['Privilege escalation attempt','high','Access'],['Unusual data export','high','Data'],['MFA fatigue prompts','med','Identity'],['New device sign-in','med','Behaviour'],['Weak key detected','med','Crypto'],['Failed login spike','low','Behaviour'],['Password policy drift','low','Access']];
const CT=['Identity','Phishing','Access','Data','Behaviour','Crypto'],PC=['#14b8a6','#6366f1','#8b5cf6','#0ea5e9','#64748b','#ec4899'];
const EV=[['Login success','login',8],['Login failed','login',48],['File downloaded','data',32],['Privilege change','access',62],['Bulk export','data',78],['Logout','login',3],['New device','login',58],['Geo anomaly','login',88]],LOC=['Pune, IN','Delhi, IN','Mumbai, IN','Berlin, DE','Lagos, NG','Austin, US'];
const ipx=()=>[ri(11,223),ri(0,255),ri(0,255),ri(1,254)].join('.');
let nid=1040;const mkA=(a,t)=>{const x=t||pk(AT);return{id:++nid,t:x[0],sev:x[1],cat:x[2],u:pk(US).n,ip:ipx(),ago:a,st:'open'}};
const mkL=m=>{const e=pk(EV);return{m,u:pk(US).n,ev:e[0],k:e[1],ip:ipx(),loc:pk(LOC),risk:Math.min(99,e[2]+ri(0,15))}};
const SM=['http://paypa1-secure-login.verify-account.xyz/update?id=1 URGENT: verify your password within 24 hours','https://www.amazon.in/gp/your-account','Dear customer, your SBI KYC is suspended. Click here: http://bit.ly/3xKycNow to avoid account blocked','http://192.168.44.12/login.php'];
const S={live:1,f:{as:'all',aq:'',uq:'',ur:0,lq:'',lt:'all'},us:US,
al:Array.from({length:18},()=>{const x=mkA(ri(2,700));x.st=pk(['open','open','open','ack','resolved','escalated']);return x}).sort((a,b)=>a.ago-b.ago),
lg:Array.from({length:60},(_,i)=>mkL(i*7+ri(0,6))),tr:Array.from({length:40},()=>ri(22,60)),sp:Array.from({length:4},()=>Array.from({length:12},()=>ri(20,80))),
hm:Array.from({length:7},(_,d)=>Array.from({length:24},(_,h)=>Math.max(.05,(h>8&&h<19?.55:.12)+rnd()*.4-(d>4?.3:0)))),
ky:[['Primary signing key','RSA',4096,41],['Database field encryption','AES-GCM',256,212],['Session token HMAC','HMAC-SHA256',256,97],['Legacy API key','RSA',1024,640],['Backup vault key','AES-GCM',256,18]].map(([n,a,b,d])=>({n,a,b,d})),
ce:[['app.acme.in',112],['api.acme.in',48],['vpn.acme.in',130],['mail.acme.in',9]],
se:US.slice(0,6).map(u=>({u:u.n,dev:pk(['Chrome · Windows','Safari · iPhone','Firefox · Linux','Edge · Windows']),ip:ipx(),loc:pk(LOC),m:ri(1,240)})),
pm:{Admin:[1,1,1,1,1],Analyst:[1,0,1,0,0],Engineer:[1,1,0,0,1],Finance:[1,1,1,0,0],HR:[1,1,0,0,0],Viewer:[1,0,0,0,0]},
pol:{mfa:1,legacy:1,pwless:0,idle:1},nt:{em:1,pu:1,al:1,wk:0},cf:{name:'Lakshay',email:'lakshay@acme.in',org:'Acme Labs',thr:70},pin:SM[0]};
S.ap={};S.au=[];S.sel=DIR[0].u;S.eve=0;S.bb=bb84(0);S.sh=null;
const PM=['Read','Write','Export','Users','Keys'],PL={mfa:'Require MFA for admins',legacy:'Block legacy authentication',pwless:'Passwordless sign-in',idle:'Auto sign-out after 15 min idle'},NT={em:'Email digests',pu:'Push alerts for critical events',al:'Notify on every new alert',wk:'Weekly summary report'};
const BR=['paypal','amazon','google','microsoft','apple','paytm','hdfc','icici','sbi','netflix','instagram','facebook'];
function scan(s){const f=[];let sc=0;const add=(n,t)=>{sc+=n;f.push([n,t])};
const um=s.match(/(?:https?:\/\/)?[^\s\/]+\.[a-z]{2,}[^\s]*|(?:https?:\/\/)?\d{1,3}(?:\.\d{1,3}){3}[^\s]*/i),u=um?um[0]:'';
if(u){const rest=u.replace(/^https?:\/\//i,''),auth=rest.split(/[\/?#]/)[0],h=auth.split('@').pop().split(':')[0].toLowerCase(),L=h.split('.'),reg=L.slice(-2).join('.');
if(/^http:/i.test(u))add(15,'Uses plain HTTP, so traffic is not encrypted');
if(/^\d+(\.\d+){3}$/.test(h))add(30,'Host is a raw IP address');
if(auth.includes('@'))add(25,'Contains “@”, which can hide the real destination');
if(h.includes('xn--'))add(30,'Punycode domain, possible lookalike characters');
if(L.length>3)add(15,'Unusually deep subdomain chain ('+L.length+' labels)');
if(/\.(xyz|top|click|tk|zip|gq|work|support|cf)$/.test(h))add(20,'Low-reputation top-level domain');
if(/^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|rb\.gy|is\.gd)$/.test(reg))add(15,'URL shortener hides the final destination');
const d=h.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/5/g,'s'),b=BR.find(x=>d.includes(x));
if(b&&!new RegExp('(^|\\.)'+b+'\\.(com|in|co\\.in|net)$').test(h))add(35,'Imitates “'+b+'” but is not its real domain');
if(h.split('-').length>3)add(10,'Many hyphens in the domain');
if(u.length>75)add(10,'Very long URL')}else f.push([0,'No link found. Only message wording was checked']);
const k=[...new Set((s.match(/urgent|verify|suspend|password|otp|kyc|within 24|click here|act now|gift|winner|blocked/gi)||[]).map(x=>x.toLowerCase()))];
if(k.length)add(Math.min(24,k.length*8),'Pressure or credential wording: '+k.join(', '));
sc=Math.min(100,sc);if(!f.some(x=>x[0]))f.push([0,'No known phishing patterns detected']);
return{s,sc,v:sc<25?'Likely safe':sc<55?'Suspicious':'Phishing likely',f,t:new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}}
S.sc=[SM[1],SM[2],SM[0]].map(scan);S.res=S.sc[2];
const oc=s=>S.al.filter(a=>a.sev==s&&a.st!='resolved').length,score=()=>Math.max(0,Math.min(100,Math.round(100-S.tr[S.tr.length-1]*.4-oc('crit')*3-oc('high')*1.5)));
const rc=r=>r>=70?'var(--cr)':r>=40?'var(--wa)':'var(--ok)',pill=s=>`<span class="pill ${s}">${{crit:'Critical',high:'High',med:'Medium',low:'Low'}[s]||s}</span>`;
const ic=d=>`<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="${d}"/></svg>`;
const N=[['overview','Overview','M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z'],['alerts','Alerts','M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0'],['users','Users','M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8'],['phishing','Phishing','M21 21l-4.3-4.3M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14'],['behaviour','Behaviour','M22 12h-4l-3 9L9 3l-3 9H2'],['identity','Identity','M3 5h18v14H3zM14 10h4M14 14h4M5 16c1-2 5-2 6 0M8 11h.01'],['crypto','Crypto','M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4'],['prefs','Settings','M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M14 4v4M8 10v4M16 16v4']];
const ln=(a,w,h)=>{const p=a.map((v,i)=>(i?'L':'M')+(i/(a.length-1)*w).toFixed(1)+' '+(h-v/100*h).toFixed(1)).join('');return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px;display:block"><path d="${p}L${w} ${h}L0 ${h}Z" fill="var(--ac)" opacity=".14"/><path d="${p}" fill="none" stroke="var(--ac)" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`};
const rg=(v,c,z=170)=>`<svg viewBox="0 0 42 42" width="${z}" height="${z}" style="transform:rotate(-90deg)"><circle cx="21" cy="21" r="16" fill="none" stroke="var(--ln)" stroke-width="3.5"/><circle cx="21" cy="21" r="16" fill="none" stroke="${c}" stroke-width="3.5" stroke-linecap="round" stroke-dasharray="${v/100*100.5} 100.5"/></svg>`;
const dn=d=>{const t=d.reduce((a,x)=>a+x[1],0)||1;let o=0;return `<svg viewBox="0 0 42 42" width="140" height="140" style="transform:rotate(-90deg)"><circle cx="21" cy="21" r="15.9" fill="none" stroke="var(--ln)" stroke-width="5"/>${d.map((x,i)=>{const p=x[1]/t*100,s=`<circle cx="21" cy="21" r="15.9" fill="none" stroke="${PC[i]}" stroke-width="5" stroke-dasharray="${p} ${100-p}" stroke-dashoffset="${-o}"/>`;o+=p;return s}).join('')}</svg>`};
const hd=(t,s,r='')=>`<div class="hd"><div><h1>${t}</h1><p class="mu">${s}</p></div><div class="r">${r}</div></div>`,kv=a=>a.map(([k,v])=>`<div class="kv"><span class="mu">${k}</span><span>${v}</span></div>`).join('');
const chips=(a,c,act)=>a.map(([v,l])=>`<button class="b ${c==v?'p':''}" data-a="${act}" data-v="${v}">${l}</button>`).join(''),tgl=(L,o)=>Object.entries(L).map(([k,l])=>`<div class="row"><span>${l}</span><button class="sw ${S[o][k]?'on':''}" data-a="tg" data-o="${o}" data-k="${k}"></button></div>`).join('');
const aR=()=>S.al.filter(a=>(S.f.as=='all'||a.sev==S.f.as)&&(a.t+a.u+a.ip+a.id).toLowerCase().includes(S.f.aq.toLowerCase())).map(a=>`<tr data-a="al" data-id="${a.id}"><td class="mono">#${a.id}</td><td><b>${a.t}</b><div class="mu">${a.cat}</div></td><td>${pill(a.sev)}</td><td>${a.u}</td><td class="mono">${a.ip}</td><td>${ago(a.ago)}</td><td><span class="pill ${a.st}">${a.st}</span></td></tr>`).join('')||'<tr><td colspan=7 class="mu">No alerts match.</td></tr>';
const uR=()=>S.us.filter(u=>(u.n+u.r).toLowerCase().includes(S.f.uq.toLowerCase())&&(!S.f.ur||u.risk>=70)).map(u=>`<tr data-a="us" data-e="${u.e}"><td><b>${u.n}</b><div class="mu">${u.e}</div></td><td>${u.r}</td><td><span class="pill ${u.mfa?'low':'high'}">${u.mfa?'MFA on':'MFA off'}</span></td><td><span class="bar"><i style="width:${u.risk}%;background:${rc(u.risk)}"></i></span>${u.risk}</td><td>${ago(u.seen)}</td><td><span class="pill ${u.lock?'crit':'low'}">${u.lock?'Locked':'Active'}</span></td></tr>`).join('')||'<tr><td colspan=6 class="mu">No users match.</td></tr>';
const lR=()=>S.lg.filter(l=>(S.f.lt=='all'||(S.f.lt=='anom'?l.risk>=60:l.k==S.f.lt))&&(l.u+l.ev+l.ip+l.loc).toLowerCase().includes(S.f.lq.toLowerCase())).slice(0,60).map(l=>`<div class="lg ${l.risk>=60?'an':''}"><span class="mono mu">${ago(l.m)}</span><span><b>${l.ev}</b> · ${l.u}</span><span class="mono mu">${l.ip} · ${l.loc}</span><span class="pill ${l.risk>=60?'crit':l.risk>=40?'high':'low'}">${l.risk}</span></div>`).join('')||'<p class="mu">No events match.</p>';
const ks=k=>k.a=='RSA'&&k.b<2048?['Weak','crit']:k.d>365?['Rotate now','crit']:k.d>180?['Due soon','high']:['Healthy','low'];
