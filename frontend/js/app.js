const cur=()=>{const h=location.hash.slice(1);return P[h]?h:'overview'},eff=()=>H.dataset.theme||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
const nv=()=>`<div class="br">${ic('M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5zM8.5 12l2.5 2.5L16 9.5')}<span>SecureID <b>Shield</b></span></div>`+N.map(n=>`<a href="#${n[0]}" class="${cur()==n[0]?'on':''}">${ic(n[2])}<span>${n[1]}</span>${n[0]=='alerts'&&oc('crit')?`<em>${oc('crit')}</em>`:''}</a>`).join('');
const tp=()=>`<span class="mu"><b style="color:var(--ink)">${S.cf.org}</b> · Production</span><div class="r"><span class="pill ${S.live?'low':'high'}">● ${S.live?'Live demo stream':'Paused'}</span><button class="b" data-a="th">${eff()=='dark'?'Light mode':'Dark mode'}</button></div>`;
function render(){$('#nv').innerHTML=nv();$('#tp').innerHTML=tp();$('#mn').innerHTML=P[cur()]()}
const toast=m=>{const t=$('#ts');t.textContent=m;t.classList.add('o');clearTimeout(toast.h);toast.h=setTimeout(()=>t.classList.remove('o'),2200)};
const dro=h=>{$('#dr').innerHTML='<button class="b" data-a="cl" style="float:right">Close</button>'+h;$('#dr').classList.add('o')};
function drA(){const a=S.al.find(x=>x.id==S.open);dro(`<h2>${a.t}</h2><p>${pill(a.sev)} <span class="pill ${a.st}">${a.st}</span></p><div style="margin:14px 0">${kv([['Alert ID','#'+a.id],['Category',a.cat],['User',a.u],['Source IP',a.ip],['Detected',ago(a.ago)]])}</div><div class="r">${[['ack','Acknowledge'],['escalated','Escalate'],['resolved','Resolve']].map(([s,l])=>`<button class="b ${s=='resolved'?'p':''}" data-a="st" data-s="${s}" data-id="${a.id}">${l}</button>`).join('')}</div>`)}
function drU(){const u=S.us.find(x=>x.e==S.open);dro(`<h2>${u.n}</h2><p><span class="pill ${u.lock?'crit':'low'}">${u.lock?'Locked':'Active'}</span></p><div style="margin:14px 0">${kv([['Email',u.e],['Role',u.r],['MFA',u.mfa?'Enabled':'Not enrolled'],['Risk score',`<span class="bar"><i style="width:${u.risk}%;background:${rc(u.risk)}"></i></span>${u.risk}`],['Last seen',ago(u.seen)]])}</div><div class="r"><button class="b p" data-a="lk" data-e="${u.e}">${u.lock?'Unlock account':'Lock account'}</button><button class="b" data-a="mf" data-e="${u.e}">Reset MFA</button><button class="b" data-a="rs" data-e="${u.e}">Revoke sessions</button></div>`)}
const A={};
A.sel=d=>{S.sel=d.u;render()};
A.cu=d=>{const k=S.sel,x=+d.x,l=S.ap[k]=S.ap[k]||[],was=l.length>=3;l.includes(x)?l.splice(l.indexOf(x),1):l.push(x);
if(!was&&l.length>=3){S.au.unshift([new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}),k+' revealed','approved by '+l.map(i=>CU[i-1]).join(', ')]);toast('Identity recovered from '+l.length+' shares')}render()};
A.rs2=()=>{S.ap[S.sel]=[];render()};
A.sch=d=>{const p=2039,q=1019,g=4,x=ri(2,q-1),y=mp(g,x,p),r=ri(1,q-1),t=mp(g,r,p),c=ri(1,q-1),s=d.v=='cheat'?ri(1,q-1):(r+c*x)%q;S.sh={y,t,c,s,ok:mp(g,s,p)==t*mp(y,c,p)%p};render()};
A.eve=()=>{S.eve^=1;S.bb=bb84(S.eve);render()};A.bbr=()=>{S.bb=bb84(S.eve);render()};
A.cl=()=>$('#dr').classList.remove('o');A.al=d=>{S.open=d.id;drA()};A.us=d=>{S.open=d.e;drU()};
A.st=d=>{const a=S.al.find(x=>x.id==d.id);a.st=d.s;API.updateAlert(a.id,{status:d.s});toast('Alert #'+a.id+' marked '+d.s);render();drA()};
A.lk=d=>{const u=S.us.find(x=>x.e==d.e);u.lock=!u.lock;API.updateUser(u.e,{locked:u.lock});toast(u.n+(u.lock?' locked':' unlocked'));render();drU()};
A.mf=d=>{const u=S.us.find(x=>x.e==d.e);u.mfa=false;API.updateUser(u.e,{mfa:false});toast('MFA reset. '+u.n+' must re-enrol');render();drU()};
A.rs=d=>toast('All sessions revoked for '+S.us.find(x=>x.e==d.e).n);
A.fa=d=>{S.f.as=d.v;render()};A.fl=d=>{S.f.lt=d.v;render()};A.fu=()=>{S.f.ur^=1;render()};
A.pz=()=>{S.live^=1;render()};A.sim=()=>{S.al.unshift(mkA(0,['Simulated ransomware beacon','crit','Data']));S.tr.push(86);S.tr.shift();toast('Critical incident simulated');render()};
A.sc=()=>{const v=$('#pin').value.trim();if(!v)return toast('Paste something to scan first');S.pin=v;S.res=scan(v);S.sc.unshift(S.res);API.saveScan(S.res);render()};
A.sm=d=>{$('#pin').value=SM[+d.x];A.sc()};A.hr=d=>{S.res=S.sc[+d.x];S.pin=S.res.s;render()};
A.pm=d=>{S.pm[d.r][+d.x]^=1;API.saveSetting('access',S.pm);render()};A.tg=d=>{S[d.o][d.k]^=1;API.saveSetting(d.o,S[d.o]);render()};A.rv=d=>{const s=S.se.splice(+d.x,1)[0];API.revokeSession(s);toast('Session revoked for '+s.u);render()};
A.rot=d=>{const k=S.ky[+d.x];k.d=0;if(k.a=='RSA'&&k.b<2048)k.b=3072;API.rotateKey(k.n);toast(k.n+' rotated');render()};
const setTh=v=>{v=='system'?delete H.dataset.theme:H.dataset.theme=v;try{v=='system'?localStorage.removeItem('th'):localStorage.setItem('th',v)}catch(e){}render()};
A.th=()=>setTh(eff()=='dark'?'light':'dark');A.tm=d=>setTh(d.v);A.sv=()=>{API.saveSetting('profile',S.cf);toast(API.live?'Settings saved':'Settings saved for this session')};
const I={aq:t=>{S.f.aq=t.value;$('#tb').innerHTML=aR()},uq:t=>{S.f.uq=t.value;$('#tb').innerHTML=uR()},lq:t=>{S.f.lq=t.value;$('#tb').innerHTML=lR()},
cf:t=>{S.cf[t.dataset.k]=t.dataset.k=='thr'?+t.value:t.value;if(t.dataset.k=='thr')$('#tv').textContent=t.value},
hs:async t=>{const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t.value));$('#ho').textContent=[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')},
pw:t=>{const v=t.value,p=(/[a-z]/.test(v)?26:0)+(/[A-Z]/.test(v)?26:0)+(/\d/.test(v)?10:0)+(/[^\w]/.test(v)?33:0),b=v?Math.round(v.length*Math.log2(p||1)):0,l=b<40?['Weak','var(--cr)']:b<60?['Fair','var(--wa)']:b<80?['Strong','var(--ok)']:['Excellent','var(--ok)'],s=2**b/1e10,
tm=s<1?'instantly':s<60?Math.round(s)+' seconds':s<3600?Math.round(s/60)+' minutes':s<86400?Math.round(s/3600)+' hours':s<3.15e7?Math.round(s/86400)+' days':s<3.15e9?Math.round(s/3.15e7)+' years':'centuries';
$('#pr').innerHTML=v?`<b style="color:${l[1]};font-size:18px">${l[0]}</b> · ${b} bits<span class="bar" style="display:block;width:100%;margin:8px 0"><i style="width:${Math.min(100,b)}%;background:${l[1]}"></i></span>Offline guessing at 10 billion tries per second: <b>${tm}</b>`:'Enter a passphrase to estimate entropy.'}};
document.addEventListener('click',e=>{const t=e.target.closest('[data-a]');if(t&&A[t.dataset.a])A[t.dataset.a](t.dataset,t)});
document.addEventListener('input',e=>{const t=e.target.closest('[data-i]');if(t&&I[t.dataset.i])I[t.dataset.i](t)});
addEventListener('hashchange',()=>{A.cl();render();scrollTo(0,0)});
try{const t=localStorage.getItem('th');if(t)H.dataset.theme=t}catch(e){}
setInterval(()=>{if(!S.live||API.live)return;const t=S.tr;t.push(Math.max(12,Math.min(88,t[t.length-1]+(rnd()-.5)*12)));t.shift();
if(rnd()<.3){S.al.unshift(mkA(0));S.al.length>40&&S.al.pop()}if(rnd()<.7){S.lg.unshift(mkL(0));S.lg.length>120&&S.lg.pop()}
const p=cur();if(p=='overview')render();else{$('#nv').innerHTML=nv();if(p=='alerts')$('#tb').innerHTML=aR();if(p=='behaviour')$('#tb').innerHTML=lR()}},3000);
render();
const refresh=()=>{const p=cur();if(p=='overview')render();else{$('#nv').innerHTML=nv();if(p=='alerts')$('#tb').innerHTML=aR();if(p=='behaviour')$('#tb').innerHTML=lR()}};
API.boot().then(d=>{if(d){Object.assign(S,d);render()}}).catch(e=>{console.error(e);toast('Could not reach the backend')});
API.subscribe(m=>{if(S.live){m.type=='alert'&&S.al.unshift(m.data);m.type=='log'&&S.lg.unshift(m.data);m.type=='risk'&&(S.tr.push(m.data),S.tr.shift());refresh()}});
