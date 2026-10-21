'use strict';
const $ = selector => document.querySelector(selector);
let csrf = '', configured = false, username = null, currentPage = 'Overview', pollTimer = null;
const pages = [
  ['Overview','◈','A clear view of your network security workspace.'],
  ['Dataset Analysis','▤','Inspect dataset records, missing values, and attack distributions.'],
  ['Model Training','◎','Train and evaluate your Random Forest classifiers.'],
  ['Traffic Prediction','⌁','Analyze compatible NSL-KDD records using the trained model.'],
  ['Live Monitoring','◉','Inspect authorized traffic and detect threshold crossings.'],
  ['Simulation Mode','▷','Test both detection rules without transmitting packets.'],
  ['Network Events','▦','Review saved live and simulated packet metadata.'],
  ['Alert History','⚑','Investigate predictions and source-based rule alerts.'],
  ['Account','⚙','Manage your administrator password and sessions.']
];
function node(tag, text, className) {
  const element=document.createElement(tag);
  if(text!==undefined && text!==null) element.textContent=String(text);
  if(className) element.className=className;
  return element;
}
function toast(message,error=false) {
  const box=$('#toast');box.textContent=message;box.className='toast'+(error?' error':'');box.hidden=false;
  clearTimeout(toast.timer);toast.timer=setTimeout(()=>box.hidden=true,6500);
}
async function api(path,options={}) {
  const headers={...(options.headers||{})};
  if(options.method && options.method!=='GET') headers['X-CSRF-Token']=csrf;
  if(options.body && !(options.body instanceof FormData)) headers['Content-Type']='application/json';
  const base = (window.API_BASE_URL || '/api').replace(/\/$/, '');
  const response=await fetch(base+path,{credentials:window.API_BASE_URL?'include':'same-origin',...options,headers});
  const result=await response.json();
  if(response.status===401){ await showAuth(); throw new Error(result.error||'Please sign in again.'); }
  if(!response.ok) throw new Error(result.error||'Request failed.');
  if(result.csrf) csrf=result.csrf;
  return result;
}
async function action(button,task){
  const previous=button.textContent;button.disabled=true;button.textContent='Working…';
  try{return await task();}catch(error){toast(error.message,true);}finally{button.disabled=false;button.textContent=button.id==='auth-submit'?(configured?'Sign in':'Create admin account'):previous;}
}
function notice(parent,text,type=''){const item=node('div',text,'notice '+type);parent.append(item);return item;}
function panel(parent,title){const box=node('section',null,'panel');if(title)box.append(node('h3',title));parent.append(box);return box;}
function metrics(parent,items){const grid=node('div',null,'metrics');for(const [label,value,hint]of items){const item=node('div',null,'metric');item.append(node('div',label,'label'),node('strong',value),node('small',hint||''));grid.append(item);}parent.append(grid);}
function table(parent,records,columns){
  if(!records||!records.length){parent.append(node('div','No records to display.','table-empty'));return;}
  const wrap=node('div',null,'table-wrap'),tab=node('table'),head=node('thead'),row=node('tr');
  const fields=columns||Object.keys(records[0]);
  for(const field of fields)row.append(node('th',field.replaceAll('_',' ')));
  head.append(row);tab.append(head);const body=node('tbody');
  for(const record of records){const tr=node('tr');for(const field of fields){const value=record[field];const td=node('td');const text=typeof value==='object'&&value!==null?JSON.stringify(value):value??'—';
      if(['status','mode','severity','attack_type'].includes(field)){const badge=node('span',text,'badge'+(['Attack','High','Port Scan','High Traffic Rate'].includes(value)?' attack':value==='Simulation'?' simulation':''));td.append(badge);}else td.textContent=String(text);
      td.title=String(text);tr.append(td);}body.append(tr);}
  tab.append(body);wrap.append(tab);parent.append(wrap);
}
function download(parent,url,label='Download CSV'){const link=node('a',label,'button-link');link.href=url;parent.append(link);return link;}
function exportJson(parent,object,name){const button=node('button','Download evaluation JSON');button.onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(object,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};parent.append(button);}
function select(parent,label,options){const container=node('label',label),input=node('select');for(const item of options){const isObj=typeof item==='object'&&item!==null;const opt=node('option',isObj?(item.name||item.label||item.id):item);opt.value=isObj?(item.id||item.value):item;input.append(opt);}container.append(input);parent.append(container);return input;}
function field(parent,label,type='text',value=''){const container=node('label',label),input=node('input');input.type=label&&label.toLowerCase().includes('search')?'search':type;input.value=value;if(input.type==='search')input.placeholder=label;container.append(input);parent.append(container);return input;}
function plot(parent,records,labelKey,valueKey){
  const canvas=node('canvas');canvas.width=850;canvas.height=260;canvas.setAttribute('aria-label','Bar chart');parent.append(canvas);
  const ctx=canvas.getContext('2d');ctx.fillStyle='#101c2e';ctx.fillRect(0,0,850,260);
  if(!records.length){ctx.fillStyle='#8d9fb7';ctx.font='14px Segoe UI';ctx.fillText('Analyze records to populate this chart.',25,120);return;}
  const max=Math.max(...records.map(r=>Number(r[valueKey])),1),barWidth=Math.min(90,650/records.length),gap=barWidth*.45;
  records.forEach((record,index)=>{const x=55+index*(barWidth+gap),height=Number(record[valueKey])/max*160;ctx.fillStyle='#4de2e0';ctx.fillRect(x,200-height,barWidth,height);ctx.fillStyle='#adbed0';ctx.font='13px Segoe UI';ctx.fillText(String(record[labelKey]),x,225);ctx.fillStyle='#e0f7f2';ctx.fillText(String(record[valueKey]),x,190-height);});
}
async function showAuth(){
  clearInterval(pollTimer);pollTimer=null;
  $('#app-shell').hidden=true;$('#auth-screen').hidden=false;
  const state=await api('/session');configured=state.configured;username=state.username;
  $('#auth-title').textContent=configured?'Welcome back':'Set up your workspace';
  $('#auth-description').textContent=configured?'Sign in to your network protection dashboard.':'Create your administrator account. Choose a password of at least 12 characters.';
  $('#confirm-label').hidden=configured;$('#confirm-password').required=!configured;
  $('#password').minLength=configured?0:12;$('#password').autocomplete=configured?'current-password':'new-password';
  $('#auth-submit').textContent=configured?'Sign in':'Create admin account';
  if(username)await showApp();
}
async function showApp(){
  $('#auth-screen').hidden=true;$('#app-shell').hidden=false;$('#signed-user').textContent='Signed in as '+username;
  const gs=$('#global-search');
  if(gs&&!gs.dataset.ready){
    gs.dataset.ready='true';
    gs.onkeydown=(e)=>{
      if(e.key==='Enter'){
        const q=gs.value.trim();
        if(q){
          navigate('Alert History').then(()=>{
            setTimeout(()=>{
              const s=document.querySelector('.toolbar input[type=search]');
              const b=document.querySelector('.toolbar button.primary');
              if(s){s.value=q;if(b)b.click();}
            },150);
          });
        }
      }
    };
  }
  await navigate('Overview');
}
$('#auth-form').addEventListener('submit',async event=>{
  event.preventDefault();$('#auth-message').textContent='';
  await action($('#auth-submit'),async()=>{
    const values={username:$('#username').value,password:$('#password').value,confirm_password:$('#confirm-password').value};
    if(!configured && values.password!==values.confirm_password)throw new Error('Passwords do not match.');
    const response=await api(configured?'/login':'/setup',{method:'POST',body:JSON.stringify(values)});
    $('#password').value='';$('#confirm-password').value='';
    if(configured){username=response.username;await showApp();}else{await showAuth();toast('Administrator created. Sign in with your new credentials.');}
  });
});
$('#logout').onclick=()=>action($('#logout'),async()=>{await api('/logout',{method:'POST',body:'{}'});username=null;await showAuth();});
for(const [name,icon]of pages){const button=node('button');button.append(node('span',icon),node('b',name));button.dataset.page=name;button.onclick=()=>navigate(name);$('#navigation').append(button);}
async function navigate(name){
  clearInterval(pollTimer);pollTimer=null;currentPage=name;
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===name));
  $('#page-title').textContent=name;$('#page-crumb').textContent=name.toUpperCase();$('#page-subtitle').textContent=pages.find(p=>p[0]===name)[2];
  const content=$('#content');content.replaceChildren();const loading=node('div','Loading workspace…','loader');content.append(loading);
  try{await renderers[name](content);}catch(error){notice(content,error.message,'error');}finally{loading.remove();}
}
const renderers={};
renderers.Overview=async content=>{
  const data=await api('/overview');
  const hero=node('div',null,'hero');hero.append(node('span','SECURITY OPERATIONS / LOCAL WORKSPACE','eyebrow'),node('h2','Understand your network traffic.'),node('p','Inspect records, investigate threshold alerts, and explore machine learning predictions from one workspace.'));content.append(hero);
  metrics(content,[['Records analyzed',data.total,'Saved ML prediction events'],['Normal predictions',data.normal,'Model-classified normal records'],['Attack predictions',data.attack,'Model-classified suspicious records'],['Binary test accuracy',data.model.ready?(data.model.accuracy*100).toFixed(2)+'%':'Not trained','Held-out NSL-KDD evaluation']]);
  const grid=node('div',null,'grid');content.append(grid);const chart=panel(grid,'ML prediction distribution');plot(chart,data.distribution,'category','records');
  const status=panel(grid,'Active model');if(data.model.ready){status.append(node('p','Random Forest · NSL-KDD'),node('p',Number(data.model.train_records).toLocaleString()+' training records / '+Number(data.model.test_records).toLocaleString()+' testing records','muted'),node('p','Created '+data.model.created_at.slice(0,10),'muted'));}else notice(status,data.model.message,'warning');
  metrics(content,[['Live packets',data.network.Live.events,'Captured metadata'],['Live rule alerts',data.network.Live.alerts,'Threshold-based indicators'],['Simulation events',data.network.Simulation.events,'Synthetic metadata'],['Simulation alerts',data.network.Simulation.alerts,'Excluded from live alert counts']]);
  table(panel(content,'Recent live rule alerts'),data.recent_rules,['timestamp','source_ip','attack_type','severity','confidence']);
  table(panel(content,'Recent ML attack predictions'),data.recent_predictions,['created_at','category','model_score','recommendation']);
  notice(content,'Academic prototype: rule thresholds indicate suspicious activity; model estimates do not prove an attack. No automatic blocking is performed.');
};
renderers['Dataset Analysis']=async content=>{
  const form=panel(content,'Inspect an NSL-KDD dataset');const input=field(form,'Original .txt or named .csv','file');input.accept='.txt,.csv';const button=node('button','Analyze dataset','primary');form.append(button);const output=node('div');content.append(output);
  button.onclick=()=>action(button,async()=>{if(!input.files.length)throw new Error('Choose a dataset file.');const body=new FormData();body.append('file',input.files[0]);const result=await api('/dataset',{method:'POST',body});output.replaceChildren();metrics(output,[['Records',result.records],['Input features',41],['Missing cells',result.missing.reduce((n,x)=>n+x.Missing,0)],['Categories',Object.keys(result.classes).length]]);plot(panel(output,'Class distribution'),Object.entries(result.classes).map(([category,records])=>({category,records})),'category','records');table(panel(output,'First 100 records'),result.preview);table(panel(output,'Missing values'),result.missing);table(panel(output,'Numeric statistics'),result.statistics);});
};
function modelReport(parent,report){
  parent.replaceChildren();const metadata=report.metrics;const box=panel(parent,'Measured evaluation');const choice=select(box,'Evaluation task',['binary','category','workflow_category']);const results=node('div');box.append(results);
  function show(){results.replaceChildren();const data=metadata[choice.value];metrics(results,[['Accuracy',(data.accuracy*100).toFixed(2)+'%'],['Precision · weighted',(data.precision_weighted*100).toFixed(2)+'%'],['Recall · weighted',(data.recall_weighted*100).toFixed(2)+'%'],['F1 · weighted',(data.f1_weighted*100).toFixed(2)+'%']]);const perClass=Object.entries(data.per_class).filter(([,v])=>typeof v==='object').map(([category,v])=>({category,...v}));table(results,perClass);const matrix=data.confusion_matrix.map((row,i)=>({actual:data.labels[i],...Object.fromEntries(row.map((v,j)=>[data.labels[j],v]))}));results.append(node('h3','Confusion matrix · actual rows / predicted columns','section-gap'));table(results,matrix);}
  choice.onchange=show;show();
  if(metadata.train_name.toLowerCase().includes('synthetic'))notice(box,'SYNTHETIC DEMO MODEL — these scores do not measure real intrusion detection performance.','warning');
  if(metadata.train_test_feature_overlap)notice(box,metadata.train_test_feature_overlap+' feature vectors appear in both datasets; inspect overlap before drawing conclusions.','warning');
  notice(box,'Test file: '+metadata.test_name+' · '+metadata.test_records+' records. Category evaluates the independent model; workflow_category evaluates the displayed category after binary gating.');
  exportJson(box,metadata,'evaluation.json');if(report.importance)table(panel(parent,'Top transformed feature importances'),report.importance);
}
renderers['Model Training']=async content=>{
  const form=panel(content,'Train the detection models');const controls=node('div',null,'toolbar');form.append(controls);const source=select(controls,'Dataset source',['Included NSL-KDD','Uploaded datasets','Synthetic quick demo']);const trees=field(controls,'Trees per forest','number',150);trees.min=10;trees.max=500;const uploads=node('div',null,'grid');form.append(uploads);const trainFile=field(uploads,'Training file','file'),testFile=field(uploads,'Testing file','file');trainFile.accept=testFile.accept='.txt,.csv';uploads.hidden=true;source.onchange=()=>uploads.hidden=source.value!=='Uploaded datasets';const button=node('button','Train and evaluate','primary');form.append(button);notice(form,'Training runs on the backend. Keep this tab open and wait; full-dataset training may take a few minutes on your laptop. The held-out file is used only for evaluation.');const output=node('div');content.append(output);
  button.onclick=()=>action(button,async()=>{const body=new FormData();body.append('source',source.value==='Uploaded datasets'?'uploads':source.value==='Synthetic quick demo'?'synthetic':'included');body.append('trees',trees.value);if(source.value==='Uploaded datasets'){if(!trainFile.files.length||!testFile.files.length)throw new Error('Upload both datasets.');body.append('train',trainFile.files[0]);body.append('test',testFile.files[0]);}await api('/train',{method:'POST',body});modelReport(output,await api('/model'));toast('Models trained and saved.');});
  try{modelReport(output,await api('/model'));}catch(error){notice(output,error.message,'warning');}
};
renderers['Traffic Prediction']=async content=>{
  notice(content,'Probability scores are uncalibrated model estimates. Predictions use compatible NSL-KDD feature records; live packet rules operate separately.');
  const box=panel(content,'Choose a prediction input');const method=select(box,'Input method',['Included NSL-KDD sample','CSV upload','Manual record']);download(box,'/api/sample','Download input sample');const inputs=node('div',null,'section-gap');box.append(inputs);const button=node('button','Analyze records','primary');box.append(button);const results=node('div');content.append(results);let recordFields={},fileInput;
  async function inputView(){inputs.replaceChildren();recordFields={};if(method.value==='CSV upload'){fileInput=field(inputs,'Compatible CSV or original text','file');fileInput.accept='.csv,.txt';}else if(method.value==='Manual record'){const schema=await api('/schema');const grid=node('div',null,'form-grid');inputs.append(grid);for(const feature of schema.features){const input=field(grid,feature,schema.categorical.includes(feature)?'text':'number',schema.defaults[feature]);if(input.type==='number'){input.min=0;input.step=schema.rates.includes(feature)?'.01':'1';if(schema.rates.includes(feature)||schema.binary_flags.includes(feature))input.max=1;if(feature==='su_attempted')input.max=2;}recordFields[feature]=input;}}else notice(inputs,'The included sample contains 25 real feature records from the held-out NSL-KDD file, five per category. It is a workflow demonstration, not an independent evaluation.');}
  method.onchange=()=>inputView().catch(e=>toast(e.message,true));await inputView();
  button.onclick=()=>action(button,async()=>{let body;if(method.value==='CSV upload'){if(!fileInput.files.length)throw new Error('Choose an input file.');body=new FormData();body.append('file',fileInput.files[0]);}else if(method.value==='Manual record'){body=JSON.stringify({record:Object.fromEntries(Object.entries(recordFields).map(([k,v])=>[k,v.type==='number'?(v.value===''?null:Number(v.value)):v.value]))});}else body=JSON.stringify({sample:true});const data=await api('/predict',{method:'POST',body});results.replaceChildren();notice(results,data.count+' records analyzed and saved. Showing '+data.shown+'.','success');if(Object.keys(data.warnings).length)notice(results,'Unseen categories encoded as zero indicators: '+JSON.stringify(data.warnings),'warning');table(panel(results,'Prediction results'),data.results);download(results,'/api/history/export?kind=predictions','Export prediction history');});
};
renderers['Simulation Mode']=async content=>{
  notice(content,'SAFE SIMULATION — synthetic metadata passes through the same detector as live monitoring. No packets are sent.','warning');
  const grid=node('div',null,'grid');content.append(grid);const a=panel(grid,'Port Scan');a.classList.add('rule-card');a.append(node('p','8 unique destination ports'),node('p','Within 10 seconds, grouped by source IP.','muted'));const b=panel(grid,'High Traffic Rate');b.classList.add('rule-card');b.append(node('p','100 packets'),node('p','Within 5 seconds, grouped by source IP.','muted'));
  const form=panel(content,'Run a controlled scenario');const scenario=select(form,'Scenario',['Port Scan','High Traffic Rate','Normal Traffic']);const button=node('button','Run simulation','primary');form.append(button);const output=node('div');content.append(output);
  button.onclick=()=>action(button,async()=>{const data=await api('/simulate',{method:'POST',body:JSON.stringify({scenario:scenario.value})});output.replaceChildren();metrics(output,[['Scenario',data.scenario],['Simulated events',data.events.length],['Rule alerts',data.alerts.length],['Traffic transmitted','None']]);if(!data.alerts.length)notice(output,'No thresholds crossed. This is expected for Normal Traffic.','success');table(panel(output,'Simulation alerts'),data.alerts);table(panel(output,'Synthetic event metadata'),data.events);download(output,'/api/history/export?kind=alerts&mode=Simulation','Export simulation alerts');});
};
renderers['Live Monitoring']=async content=>{
  notice(content,'Rules: 8 unique destination ports in 10 seconds; 100 packets in 5 seconds per source. Confidence describes a threshold match, not an AI probability. No NSL-KDD predictions are made from raw packets.');
  const box=panel(content,'Authorized local packet capture'),toolbar=node('div',null,'toolbar');box.append(toolbar);const network=await api('/interfaces');const iface=select(toolbar,'Network interface',network.interfaces.length?network.interfaces:['No interface available']);const duration=field(toolbar,'Auto-stop duration · seconds','number',60);duration.min=10;duration.max=120;if(network.warning)notice(box,network.warning,'warning');const label=node('label');const authorized=node('input');authorized.type='checkbox';label.append(authorized,document.createTextNode('I am authorized to monitor this network.'));box.append(label);const actions=node('div',null,'two-actions');const start=node('button','Start capture','primary'),stop=node('button','Stop capture');actions.append(start,stop);box.append(actions);start.disabled=!network.interfaces.length;const output=node('div');content.append(output);
  start.onclick=()=>action(start,async()=>{if(!authorized.checked)throw new Error('Confirm authorization first.');const data=await api('/capture/start',{method:'POST',body:JSON.stringify({authorized:true,interface:iface.value,duration:Number(duration.value)})});toast(data.message);await update();});stop.onclick=()=>action(stop,async()=>{await api('/capture/stop',{method:'POST',body:'{}'});await update();});
  let updating=false;
  async function update(){if(updating||currentPage!=='Live Monitoring')return;updating=true;try{const data=await api('/capture',{headers:{'X-Background-Poll':'1'}});if(currentPage!=='Live Monitoring')return;output.replaceChildren();metrics(output,[['Capture',data.running?'Running':'Stopped'],['Packets observed',data.count],['Buffered events',data.events.length],['Buffered alerts',data.alerts.length]]);if(data.error)notice(output,data.error,'error');if(data.evicted_sources)notice(output,'Source limit reached; '+data.evicted_sources+' source states evicted. Coverage may be incomplete.','warning');table(panel(output,'Session rule alerts'),data.alerts);table(panel(output,'Latest packet metadata'),data.events); }catch(error){if(username)toast(error.message,true);}finally{updating=false;}}
  await update();if(currentPage==='Live Monitoring')pollTimer=setInterval(update,2000);
};
async function historyView(content,networkOnly){
  const box=panel(content,networkOnly?'Network event history':'Saved alerts and predictions');const toolbar=node('div',null,'toolbar');box.append(toolbar);
  const kind=select(toolbar,'History type',networkOnly?['Network events']:['Rule alerts','ML predictions']);const mode=select(toolbar,'Mode',['All','Live','Simulation']);const rule=select(toolbar,'Rule',['All','Port Scan','High Traffic Rate']);const status=select(toolbar,'ML status',['All','Attack','Normal']);const search=field(toolbar,'Source / destination / text search');const button=node('button','Apply filters','primary');toolbar.append(button);const output=node('div');box.append(output);let page=1,lastQuery;
  function visibility(){const ml=kind.value==='ML predictions';mode.parentElement.hidden=ml;rule.parentElement.hidden=ml||networkOnly;status.parentElement.hidden=!ml;}
  kind.onchange=()=>{page=1;visibility();load().catch(e=>toast(e.message,true));};visibility();
  async function load(){const params=new URLSearchParams({kind:networkOnly?'events':kind.value==='ML predictions'?'predictions':'alerts',mode:mode.value,attack_type:rule.value,status:status.value,search:search.value,page:String(page)});lastQuery=params;const data=await api('/history?'+params);output.replaceChildren();output.append(node('p',data.total+' matching records · Page '+page,'muted'));table(output,data.records);const actions=node('div',null,'two-actions');const previous=node('button','Previous'),next=node('button','Next');previous.disabled=page<=1;next.disabled=page*100>=data.total;previous.onclick=()=>{page--;load().catch(e=>toast(e.message,true));};next.onclick=()=>{page++;load().catch(e=>toast(e.message,true));};actions.append(previous,next);download(actions,'/api/history/export?'+lastQuery,'Export all matching records');output.append(actions);}
  button.onclick=()=>action(button,async()=>{page=1;await load();});await load();
}
renderers['Network Events']=content=>historyView(content,true);
renderers['Alert History']=content=>historyView(content,false);
renderers.Account=async content=>{
  const box=panel(content,'Change your administrator password');notice(box,'Updating the password revokes all active sessions. Sign in again with your new password.');const form=node('form');box.append(form);const old=field(form,'Current password','password'),next=field(form,'New password · at least 12 characters','password'),confirm=field(form,'Confirm new password','password');old.autocomplete='current-password';next.autocomplete=confirm.autocomplete='new-password';next.minLength=12;old.required=next.required=confirm.required=true;const button=node('button','Update password','primary');form.append(button);form.onsubmit=event=>{event.preventDefault();action(button,async()=>{await api('/password',{method:'POST',body:JSON.stringify({current_password:old.value,new_password:next.value,confirm_password:confirm.value})});username=null;await showAuth();toast('Password updated. Sign in again.');});};
};
function updateClock(){$('#clock').textContent=new Date().toLocaleString();}updateClock();setInterval(updateClock,1000);
showAuth().catch(error=>{$('#auth-title').textContent='Backend unavailable';$('#auth-description').textContent='Start backend/app.py, then open http://localhost:5000. Do not open index.html directly.';$('#auth-message').textContent=error.message;});
