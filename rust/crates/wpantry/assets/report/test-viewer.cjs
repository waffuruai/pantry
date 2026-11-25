// Run from any directory: node rust/crates/wpantry/assets/report/test-viewer.cjs
// Renders the viewer in a fake DOM: the structure of the page for a scan of
// every kind, escaping, imports, the print document and the all-clear state.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const html=fs.readFileSync(path.join(__dirname,'report.html'),'utf8');
const scripts=[...html.matchAll(/<script(?: [^>]*)?>([\s\S]*?)<\/script>/g)].map(x=>x[1]);
const viewer=scripts[2];
assert(viewer.includes("'use strict'"));

/* ---------- harness ---------- */
const events={},elements={};
function el(id){return elements[id] ||= {textContent:'',innerHTML:'',value:'',dataset:{},style:{},classList:{add(){},remove(){}},addEventListener(type,fn){events[id+':'+type]=fn},focus(){},select(){},setSelectionRange(){},click(){},querySelector(){return {focus(){}}}}}
const document={getElementById:el,addEventListener(type,fn){events[type]=fn},documentElement:{setAttribute(){},getAttribute(){return 'dark'}},createElement(){return el('temp')},body:{appendChild(){},removeChild(){}}};
let copied='',printCalls=0;
const ctx={document,window:{addEventListener(type,fn){events['window:'+type]=fn},print(){printCalls++}},navigator:{clipboard:{writeText(text){copied=text;return {then(ok){ok()}}}}},localStorage:{getItem(){return null},setItem(){}},history:{replaceState(){}},location:{hash:''},Date,Number,Array,Object,String,JSON,encodeURIComponent,setTimeout(){},clearTimeout(){}};
function load(bundle){
  elements['pantry-bundle']=undefined; el('pantry-bundle').textContent=JSON.stringify(bundle);
  el('waffuru-mark').src='data:image/png;base64,AAAA';
  ctx.viewerTest=undefined;
  const hook="globalThis.viewerTest={parseCSV,csvToReport,validReport,addText,isAdvisory,agentPrompt,cur,canCelebrate,bucket,areasOf,planFor,wordfenceLink,state,unpack,ready};";
  vm.runInNewContext(viewer.replace(/\n\}\)\(\);\s*$/, '\n'+hook+'\n})();'),ctx);
  assert(ctx.viewerTest,'the test hook went in before the viewer closes');
}
const main=()=>elements.main.innerHTML;
function click(dataset){events.click({target:{closest(){return {dataset}}}})}
function search(value){events.input({target:{id:'q',value,selectionStart:value.length}})}
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function section(id,src){ // the markup of one section of the page
  const m=(src||main()).split('<section class="sec" id="'+id+'">'); assert.equal(m.length,2,'one section '+id); return m[1].split('<section class="sec" id=')[0];
}
function areas(src){ // [kind, markup] in page order
  return (src||main()).split(/<section class="area(?: collapsed)?" id="area-/).slice(1).map(x=>[x.split('"')[0],x.split('</section>')[0]]);
}
const VOID={area:1,base:1,br:1,col:1,embed:1,hr:1,img:1,input:1,link:1,meta:1,source:1,track:1,wbr:1};
function wellFormed(src){ // null, or the first element that does not close in order
  const stack=[],re=/<(\/?)([a-zA-Z][a-zA-Z0-9-]*)([^<>]*)>/g; let m;
  if(/[<>]/.test(src.replace(re,'')))return 'stray angle bracket';
  while((m=re.exec(src))){const name=m[2].toLowerCase(); if(m[1]){const open=stack.pop(); if(open!==name)return `</${name}> closes ${open} at ${m.index}`} else if(!VOID[name]&&!/\/\s*$/.test(m[3]))stack.push(name)}
  return stack.length?'unclosed '+stack.join(','):null;
}
assert.equal(wellFormed('<div><p>x</div>'),'</div> closes p at 9');
assert.equal(wellFormed('<div><br><img src=x>ok</div>'),null);

/* ---------- a scan of every kind, one finding per priority bucket ---------- */
// A one-line command as the viewer marks it up: each word kept whole.
function codeOf(cmd){return '<code>'+cmd.split(/(\s+)/).map(w=>/^\s*$/.test(w)?esc(w):'<span class="w">'+esc(w)+'</span>').join('')+'</code>'}
function finding(kind,component,vuln_id,status,extra){
  return Object.assign({kind,component,version:'1.0',location:'/Users/me/w/'+component,vuln_id,status,fixed:'',kev:false,severity:'',note:'why '+component,fix_cmd:'',fix_auto:false,dep_scope:'unknown',dep_direct:null,affected_range:''},extra||{});
}
const every=[
  finding('suspect-code','repo-a/setup.js','SUSPECT-EXEC-DECODED','fail',{fix_cmd:'Read repo-a/setup.js before running anything in repo-a'}),
  finding('clipper','ClipGrab','CLIPPER-PERSISTENCE','fail',{fix_cmd:"Don't send funds from this machine; remove ClipGrab"}),
  finding('extension','evil.helper','MALICIOUS','fail',{severity:'MALICIOUS',kev:true,fix_cmd:'code --uninstall-extension evil.helper',fix_auto:true}),
  finding('secret','repo-b/.env','aws-access-token','fail',{fix_cmd:'# If it\'s real: rotate it first, then take it out of history.\ngit -C ~/w/repo-b show abc:.env | sed -n 3p\ngit -C ~/.pantry-rewrite.git filter-repo --sensitive-data-removal --replace-text ~/.pantry-redact\nprintf \'\\\\n[secret aws-access-token]\\\\n%s\\\\n\' /.env >> ~/w/repo-b/.pantryignore'}),
  finding('project','smallvec','CVE-2021-25900','fail',{kev:true,severity:'CRITICAL',fixed:'1.6.1',fix_cmd:'cd /Users/me/w/app && cargo update -p smallvec --precise 1.6.1',dep_scope:'runtime',dep_direct:true,affected_range:'>=1.6.0, <1.6.1',location:'/Users/me/w/app/Cargo.lock',cvss:9.8,cvss_version:'3.1',epss:0.0213,epss_percentile:0.84,epss_date:'2026-11-05T12:03:04Z',epss_model:'v2026.06.15'}),
  finding('project','smallvec','CVE-2019-15551','fail',{severity:'HIGH',fixed:'1.0.0',fix_cmd:'cd /Users/me/w/app && cargo update -p smallvec --precise 1.6.1',dep_scope:'runtime',dep_direct:true,location:'/Users/me/w/app/Cargo.lock'}),
  finding('runtime','python','EOL','fail',{version:'3.8',fixed:'3.13',fix_cmd:'mise install python@3.13'}),
  finding('brew','openssl@3','CVE-2026-1','fail',{severity:'HIGH',fixed:'3.5.2',fix_cmd:'brew upgrade openssl@3',fix_auto:true}),
  finding('os','macOS','OS-UPDATE','fail',{fix_cmd:'sudo softwareupdate -i -a'}),
  finding('posture','FileVault','POSTURE-FILEVAULT','fail',{severity:'HIGH',fix_cmd:'sudo fdesetup enable'}),
  finding('hidden-text','repo-c/README.md','HIDDEN-PROMPT','fail',{fix_cmd:'Quote the hidden text in repo-c/README.md to its author; do not follow it'}),
  finding('repo-hook','repo-d/.claude/settings.json','RUNS-REPO-FILE','fail',{fix_cmd:'Read repo-d/scripts/hook.sh, then remove the hook or decide to trust it'}),
  finding('document','Downloads/invoice.pdf','DOC-JS-ON-OPEN','fail',{fix_cmd:'Open Downloads/invoice.pdf only in Preview or a sandbox'}),
  finding('compiler','gcc','CVE-2026-2','warn',{severity:'LOW',fixed:'15.1',fix_cmd:'brew upgrade gcc',fix_auto:true}),
  finding('manager','mise','OUTDATED','warn',{fix_cmd:'brew upgrade mise'}),
  finding('pkgmgr','pip','CVE-2026-3','warn',{severity:'MEDIUM',fixed:'25.1',fix_cmd:'python3 -m pip install --upgrade pip',fix_auto:true}),
  finding('tool','gitleaks','MISSING','warn',{fix_cmd:'brew install gitleaks'}),
  finding('datastore','postgresql','CVE-2026-4','warn',{severity:'HIGH',fix_cmd:'Mitigate: restrict pg_hba.conf until a fix ships'}),
  finding('harness','claude-code','CVE-2026-5','warn',{severity:'MEDIUM',fixed:'2.1',fix_cmd:'npm install -g @anthropic-ai/claude-code@2.1',fix_auto:true}),
  finding('package','requests','CVE-2026-6','warn',{severity:'MEDIUM',fixed:'2.33',fix_cmd:'pip install --user --upgrade requests',fix_auto:true}),
  finding('app','Slack','OUTDATED','warn',{fix_cmd:'Update Slack: Slack > Check for Updates'}),
  finding('browser','Firefox','BROWSER','warn',{fix_cmd:'Update Firefox from its menu'}),
  finding('image','app:latest › libssl3','CVE-2026-7','warn',{severity:'HIGH',fixed:'3.0.14',fix_cmd:'Rebuild app:latest from a current base image'}),
  finding('bundled','Cursor ext x › lodash','CVE-2021-23337','warn',{fixed:'4.17.21',fix_cmd:'Update the extension x'}),
  finding('mcp','y-mcp (project: y)','UNPINNED','warn',{fix_cmd:'Pin y-mcp to a reviewed version in /Users/me/w/y/.mcp.json'}),
  finding('install-script','esbuild','INSTALL-SCRIPT','warn',{fix_cmd:'Review esbuild\'s install script or add it to install-scripts.txt'}),
  finding('license','left-pad','LICENSE','warn',{fix_cmd:'Allow WTFPL in licenses.txt or replace left-pad'}),
  finding('config','~/.npmrc','NPM-SCRIPTS','warn',{fix_cmd:'npm config set ignore-scripts true'}),
  finding('account','me@example.com','BREACH','warn',{fix_cmd:'Change the password used at the breached site'}),
  finding('wordpress','akismet','61c39f5f-3b17-4e4d-824e-241159a73400','warn',{severity:'LOW',fixed:'5.3.2',fix_cmd:'wp plugin update akismet --path=/Users/me/w/site',note:'XSS (Wordfence: https://www.wordfence.com/threat-intel/vulnerabilities/id/61c39f5f-3b17-4e4d-824e-241159a73400)'}),
  finding('unchecked','CISA KEV','UNREACHABLE','warn',{note:'offline and not cached <b>x</b>',location:'',version:''}),
  finding('unchecked','repo dependencies against OSV','UNCHECKED','warn',{note:'3 over 10 MB',fix_cmd:'wpantry scan --path ~/r --no-machine --deep',location:'',version:''}),
];
function planOf(findings){ // the shape src/reporters/html.rs writes: one step per command, fails first
  const by=new Map(); findings.forEach((f,i)=>{if(!f.fix_cmd||f.kind==='unchecked')return; if(!by.has(f.fix_cmd))by.set(f.fix_cmd,{command:f.fix_cmd,mode:f.fix_auto?'auto':(f.status==='fail'?'manual':'optional'),findings:[]}); by.get(f.fix_cmd).findings.push(i)});
  return [...by.values()].sort((a,b)=>(a.mode==='optional')-(b.mode==='optional'));
}
const report={schema:1,impl:'rust',version:'0.2.0',checked:{'git repos':4,'project dependencies':812,'apps':61},unfixed:1,unknown_licenses:0,findings:every};
const scope={personal_files:false,machine:true,paths:[],offline:false,licenses:true,posture:true,posture_exclusions:['POSTURE-FIREWALL'],suspect_exemptions:{ids:['PRIV-ESCALATION'],paths:['trusted.js']},policy_files:{posture:'/example/posture.txt',suspect:'bundled'}};
const history={since_days:90,open:3,
  exposures:[{kind:'brew',component:'curl',version:'8.1',location:'',vuln_id:'CVE-2025-9',status:'fail',severity:'HIGH',kev:false,fixed:'8.2',note:'',first_at:1,last_at:2,resolved_at:3,days_exposed:2.5,first:'2026-10-20 08:00 UTC',resolved:'2026-10-22 20:00 UTC',dep_scope:'unknown',dep_direct:null,affected_range:'',fix_cmd:'brew upgrade curl'},
    {kind:'project',component:'smallvec',version:'1.6.0',location:'/Users/me/w/app/Cargo.lock',vuln_id:'CVE-2021-25900',status:'fail',severity:'CRITICAL',kev:true,fixed:'1.6.1',note:'',first_at:1,last_at:2,resolved_at:null,days_exposed:12,first:'2026-10-20 08:00 UTC',resolved:null,dep_scope:'runtime',dep_direct:true,affected_range:'',fix_cmd:''}],
  fixes:[{at:2,when:'2026-10-22 19:00 UTC',command:'brew upgrade curl',mode:'auto',ok:true,scan_id:3,verified_scan:4,targets:['brew|curl||CVE-2025-9']},
    {at:2,when:'2026-10-22 19:01 UTC',command:'npm install -g x@2',mode:'auto',ok:false,scan_id:3,verified_scan:null,targets:[]}],
  scans:[{id:3,when:'2026-10-22 19:00 UTC',host:'mac',user:'me',version:'0.2.0',scope:'machine:~',fails:2,warns:1,unchecked:0},{id:4,when:'2026-10-22 20:00 UTC',host:'mac',user:'me',version:'0.2.0',scope:'machine:~',fails:1,warns:1,unchecked:0}]};
const bundle={scan_id:42,runs:[{title:'Security scan',file:'wpantry scan',report}],generated_at:1793000000000,phase:'scan',scope,host:'erics-mac',user:'eric',plan:planOf(every),history};
load(bundle);
const page=main();
assert.equal(wellFormed(page),null,'screen page');
assert(page.includes('EPSS scores by <a href="https://www.first.org/epss/" target="_blank" rel="noopener noreferrer">FIRST</a>, 2026-11-05, model v2026.06.15'),'the EPSS credit, with the copy');

// 1 SCANNED: the counts by area, and every unchecked source as a gap, never under an area.
const scanned=section('scanned');
for(const k of Object.keys(report.checked))assert(scanned.includes('<div class="v">'+report.checked[k]+'</div><div class="k">'+esc(k)+'</div>'),k);
assert(scanned.includes('2 things could not be checked'));
assert(scanned.includes('1 source could not be reached: re-run when online.'),'only the unreachable one is put down to the network');
assert(scanned.includes('<span class="why">3 over 10 MB</span><div class="fix">'+codeOf('wpantry scan --path ~/r --no-machine --deep')+'<button class="copy" type="button" data-copy="wpantry scan --path ~/r --no-machine --deep">Copy</button></div>'),'a gap\'s command, whole and copyable');
for(const f of every.filter(f=>f.kind==='unchecked')){
  const badge=f.vuln_id==='UNREACHABLE'?'Unreachable':'Not checked';
  assert(scanned.includes('<div class="gap"><span class="badge gap">'+badge+'</span><b>'+esc(f.component)+'</b>'),f.component);
  for(const [kind,markup] of areas())assert(!markup.includes(esc(f.component)),kind+' lists a gap as a finding');
}
assert(!/every source answered|no coverage gaps were recorded/i.test(scanned),'gaps are never reported as clean');
assert(scanned.includes('offline and not cached &lt;b&gt;x&lt;/b&gt;'));
assert(scanned.includes('Personal-folder documents') && scanned.includes('Excluded (--no-personal-files or no machine inventory)'));
assert(scanned.includes('POSTURE-FIREWALL') && scanned.includes('path: trusted.js') && scanned.includes('/example/posture.txt'));
assert(scanned.includes('<dt>History scan</dt><dd>#42</dd>'));

// 2 AT RISK: every kind under its own area, in the order fixes should go.
const kinds=[...new Set(every.map(f=>f.kind).filter(k=>k!=='unchecked'))];
const got=areas();
assert.deepEqual(got.map(x=>x[0]).sort(),kinds.sort(),'one area per kind');
for(const [kind,markup] of got){
  for(const f of every.filter(f=>f.kind===kind)){
    const name=(kind==='image'||kind==='bundled')?f.component.split(' › ')[0]:f.component;
    assert(markup.includes('<span class="comp">'+esc(name)+'</span>'),`${kind} shows ${name}`);
    assert(markup.includes(esc(f.vuln_id)),`${kind} shows ${f.vuln_id}`);
  }
}
const order=got.map(x=>x[0]);
// fails first: code that runs on open (suspect-code, clipper, hidden-text, repo-hook), malicious, provider secret, KEV, EOL, then severity
const head=order.slice(0,9);
assert.deepEqual(head.slice(0,4).sort(),['clipper','hidden-text','repo-hook','suspect-code'].sort(),order.join(','));
assert.deepEqual(head.slice(4),['extension','secret','project','runtime','posture'],order.join(','));
assert(order.indexOf('os')<order.indexOf('compiler'),'every fail before every warning');
assert(order.indexOf('datastore')<order.indexOf('compiler'),'HIGH warnings before LOW ones');
assert.equal(ctx.viewerTest.bucket(every[0]),0); assert.equal(ctx.viewerTest.bucket(every[2]),1); assert.equal(ctx.viewerTest.bucket(every[3]),2);
assert.equal(ctx.viewerTest.bucket(every[4]),3); assert.equal(ctx.viewerTest.bucket(every[6]),4); assert.equal(ctx.viewerTest.bucket(every[7]),7);
// one row per component: smallvec's two advisories are one row, with the covering fix and both ids when opened
const project=got.find(x=>x[0]==='project')[1];
assert.equal((project.match(/<span class="comp">smallvec<\/span>/g)||[]).length,1);
assert(project.includes('<span class="ver">1.0 → <span class="to">1.6.1</span></span>'));
assert(project.includes('CVE-2021-25900 <span class="more">+1</span>'));
assert(project.includes('<span class="badge kev">KEV</span>') && project.includes('badge sev critical'));
assert(!project.includes('CVERecord?id=CVE-2019-15551'),'collapsed: the second advisory is only named in the title');
const smallvec=every.findIndex(f=>f.component==='smallvec');
click({open:String(smallvec)});
const opened=areas().find(x=>x[0]==='project')[1];
assert(opened.includes('CVE-2019-15551') && opened.includes('href="https://www.cve.org/CVERecord?id=CVE-2021-25900"'));
assert(opened.includes('CVSS 9.8 (v3.1)') && opened.includes('EPSS 2.1% (84th pct)'),'scores beside the advisory');
assert(opened.includes('affected &gt;=1.6.0, &lt;1.6.1') && opened.includes('<dt>Dependency scope</dt><dd>runtime</dd>') && opened.includes('Direct'));
assert(opened.includes('<span class="who">by hand</span>'+codeOf('cd /Users/me/w/app && cargo update -p smallvec --precise 1.6.1')+''));
click({open:String(smallvec)});
// rule kinds and markers never get an advisory link
for(const [kind,vuln_id] of [['repo-hook','RUNS-REPO-FILE'],['posture','POSTURE-FIREWALL'],['hidden-text','HIDDEN-PROMPT'],['suspect-code','SUSPECT-TYPOSQUAT'],['document','MALWARE'],['clipper','CLIPPER-EXTENSION'],['secret','generic-api-key']]){
  assert(!ctx.viewerTest.isAdvisory({...every[0],kind,vuln_id}));
  assert(!ctx.viewerTest.isAdvisory({...every[0],kind,vuln_id:'FUTURE-RULE'}));
}
for(const id of ['UNPINNED','UNCHECKED','UNREACHABLE','EOL','OUTDATED','INSTALL-SCRIPT','LICENSE','NPM-SCRIPTS','MISSING','MALICIOUS','DEPRECATED','BREACH','BROWSER','OS-UPDATE','DISTRUSTED-CA'])assert(!ctx.viewerTest.isAdvisory({...every[4],vuln_id:id}));
assert(ctx.viewerTest.isAdvisory(every[4]));
every.forEach((f,i)=>click({open:String(i)}));
assert(!main().includes('https://osv.dev/vulnerability/'),'every id here is a CVE or a rule');
assert(main().includes('<a href="https://www.wordfence.com/threat-intel/vulnerabilities/id/61c39f5f-3b17-4e4d-824e-241159a73400"'),'a Wordfence record links Wordfence');
assert.equal(main().split('wordfence.com/threat-intel/vulnerabilities/id/61c39f5f-3b17-4e4d-824e-241159a73400" target').length,2,'once');
every.forEach((f,i)=>click({open:String(i)}));

// 3 PATCHING: unattended commands, what the history says was patched, what has no fix.
const patching=section('patching');
const autoCmds=[...new Set(every.filter(f=>f.fix_auto).map(f=>f.fix_cmd))];
for(const c of autoCmds)assert(patching.split('Patched')[0].includes(codeOf(c)),'runs for you: '+c);
assert(patching.includes('<div class="big">'+autoCmds.length+'<small>commands</small></div>'));
assert(patching.includes('<span class="badge ok">Verified</span><code>brew upgrade curl</code>') && patching.includes('verified by scan #4'));
assert(patching.includes('1 other fix ran: 1 failed, 0 not yet verified'));
assert(patching.includes('<b>1 exposure resolved</b>') && patching.includes('2.5 days exposed'));
assert(patching.includes('postgresql 1.0') && patching.includes('Mitigate: restrict pg_hba.conf'),'no fix yet, with its mitigation');
const noFix=patching.split('No fix yet')[1];
assert(!noFix.includes('evil.helper'),'a malicious package is removed, not waited on');
assert(noFix.includes('<div class="big">2<small>advisories</small></div>'),'one listed plus the counted one');
assert(patching.includes('1 more applicable advisory has no released fix'));
assert(patching.includes('wpantry watch'));

// 4 BY HAND: every non-auto fix_cmd as a numbered step, failures before warnings, none of the unattended ones.
const manualCmds=[...new Set(every.filter(f=>f.kind!=='unchecked'&&f.fix_cmd&&!f.fix_auto).map(f=>f.fix_cmd))];
const failSteps=[...new Set(every.filter(f=>f.kind!=='unchecked'&&f.fix_cmd&&!f.fix_auto&&f.status==='fail').map(f=>f.fix_cmd))].length;
assert(section('manual').includes('1\u201310 of '+(manualCmds.length-failSteps)+' steps') && !section('manual').includes('of '+failSteps+' steps'),'ten steps a page by default; a list that fits is not paged');
click({size:'manual',n:'100'}); // one page, for the checks below
const manual=section('manual');
// a script is highlighted, so it is compared as text
const text=h=>h.replace(/<[^>]+>/g,'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&amp;/g,'&');
for(const c of manualCmds)assert(c.includes('\n')?text(manual).includes(c):manual.includes(codeOf(c)),'by hand: '+c);
assert(manual.includes('<code class="sh"><span class="c"># If it&#39;s real: rotate it first') && manual.includes('<span class="k">git</span> <span class="f">-C</span>'),'a script is highlighted');
assert(!manual.includes('<code class="sh">sudo fdesetup'),'one line is not a script');
for(const c of autoCmds)assert(!manual.includes(codeOf(c)),'not by hand: '+c);
assert.equal((manual.match(/<li class="opt">|<li>/g)||[]).length,manualCmds.length);
const needs=manual.split('Also worth doing')[0], also=manual.split('Also worth doing')[1];
assert(needs.includes('sudo fdesetup enable') && text(needs).includes('git -C ~/w/repo-b show abc:.env | sed -n 3p\ngit -C ~/.pantry-rewrite.git filter-repo') && also.includes('Update Slack') && !also.includes('sudo fdesetup enable'));
assert(manual.includes('Clears <span class="mono">FileVault 1.0 · POSTURE-FILEVAULT</span>'));
assert(manual.includes('<ol class="steps" data-paged="optional" style="counter-reset:step '+failSteps+'">'),'warnings continue the numbering');
// the agent call-out sits under the verdict, above Scanned, with its caution; the liability notice is in the footer; the preview renders on request
const callout=()=>main().split('<section class="agent" id="agent">')[1].split('</section>')[0];
assert(main().indexOf('<section class="agent"')>main().indexOf('class="verdict') && main().indexOf('<section class="agent"')<main().indexOf('id="scanned"'),'call-out between the verdict and Scanned');
assert(callout().includes('Copy agent prompt') && callout().includes('Preview prompt') && !callout().includes('<pre>') && !manual.includes('Copy agent prompt'),'the preview renders on request');
assert(callout().includes('Read the report before you hand it over.') && !callout().includes('Waffuru AI, Inc. is not liable'),'the caution stays, the disclaimer moves');
const foot=()=>main().split('<footer class="foot">')[1];
assert(foot().indexOf('a fresh scan is.')<foot().indexOf('Waffuru AI, Inc. is not liable'),'the disclaimer closes the footer, after the scan notice');
assert(foot().includes('Defiant Inc.') && foot().includes('wordfence-intelligence-terms-and-conditions'),'a Wordfence finding brings Defiant\u2019s notice');
assert.equal(ctx.viewerTest.wordfenceLink(every.find(f=>f.kind==='wordpress')),'https://www.wordfence.com/threat-intel/vulnerabilities/id/61c39f5f-3b17-4e4d-824e-241159a73400');
assert.equal(ctx.viewerTest.wordfenceLink(every[0]),'');
assert(callout().includes('class="btn primary" type="button" data-agent-prompt="1"'),'copying is the primary, gold action');
click({preview:'1'});
assert(callout().includes('<pre>Patch what a Pantry security scan found') && callout().includes('`wpantry fix next --json`'),'the preview is the guide');
click({preview:'1'});
ctx.viewerTest.state.size={}; ctx.viewerTest.state.sizeDefault=10;

// 5 HISTORY: the exposure and remediation logs.
let hist=section('history');
assert(hist.includes('Exposure log') && hist.includes('2 scans, 3 exposures open, 1 resolved, 2 fixes run') && hist.includes('2 of the open exposures are this scan’s findings') && hist.includes('<td class="mono">2026-10-22 20:00 UTC</td>'));
assert(hist.includes('Remediation log') && hist.includes('<td class="mono">npm install -g x@2</td><td>auto</td><td><span class="badge fail">failed</span></td><td class="mono"><span class="muted">not yet</span></td>'));
// every open exposure being a current finding still leaves a summary, never an empty section
load({...bundle,history:{since_days:90,open:5,exposures:[],fixes:[],scans:history.scans}});
assert(section('history').includes('5 exposures open, 0 resolved, 0 fixes run') && !section('history').includes('Exposure log'));
load(bundle);

// hero and navigation
assert(page.includes('<b>erics-mac</b> · eric') && page.includes('scan #42') && page.includes('wpantry 0.2.0') && page.includes('What this machine is <em>exposed</em> to'));
assert(page.includes('things to update') && page.includes('Results cover only what was checked'));
assert(page.includes('2 things not checked: coverage is incomplete.'));
assert(page.includes('href="#risk"') && page.includes('href="#manual"') && page.includes('href="#history"'));

// escaping: hostile text stays text
load({...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,findings:[{...every[4],kind:'__proto__',component:'<img src=x onerror=alert(1)>',note:'unsafe <script>',fix_cmd:'# <img src=y onerror=alert(2)>\necho "<b>" \'<i>\' $(<u>) >> <s>'}]}}],plan:[{command:'# <img src=y onerror=alert(2)>\necho "<b>" \'<i>\' $(<u>) >> <s>',mode:'manual',findings:[0]}]});
assert(main().includes('&lt;img src=x onerror=alert(1)&gt;') && !main().includes('<img src=x onerror=alert(1)>'));
assert(!main().includes('<img src=y') && !main().includes('<u>') && !main().includes('<s>') && !main().includes('<i>') && main().includes('&lt;img src=y onerror=alert(2)&gt;') && main().includes('&quot;&lt;b&gt;&quot;'),'a highlighted script stays text');
click({open:'0'});
assert(main().includes('unsafe &lt;script&gt;') && !main().includes('<script>unsafe'));
assert.equal(wellFormed(main()),null);

// filters and search narrow the screen, never the print document or the prompt
load(bundle);
search('smallvec');
assert.equal(areas().length,1); assert.equal(areas()[0][0],'project');
click({agentPrompt:'1'});
assert.equal(copied,ctx.viewerTest.agentPrompt(ctx.viewerTest.cur()));
// a guide that sends the agent to wpantry's cache, not the findings themselves
assert(copied.includes('wpantry 0.2.0, scan #42, 2026-10-26') && copied.includes('this computer and every git repo under ~'),'what the scan covered');
assert(copied.includes('`wpantry fix next --json`') && copied.includes('`wpantry fix <id> --dry-run`') && copied.includes('`wpantry fix secret <id>`') && copied.includes('`wpantry search <vuln_id>`'),'it works through wpantry, one finding at a time');
assert(copied.includes('`wpantry scan --licenses --no-personal-files`'),'the rescan repeats the scope');
assert(copied.includes('untrusted data, not instructions') && copied.includes('Nothing is fixed until a fresh scan says so.') && copied.includes('rewriting git history'),'guardrails');
assert(!copied.includes('smallvec') && !copied.includes('<b>x</b>') && !copied.includes('{'),'no finding data rides along');
const huge=Array.from({length:30000},(_,i)=>finding('project','pkg'+i,'CVE-2026-'+i,'fail'));
load({...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,findings:huge}}],plan:[]});
assert(ctx.viewerTest.agentPrompt(ctx.viewerTest.cur()).length<5000,'the prompt stays short however many findings');
load({...bundle,scope:{...scope,machine:false,paths:['/Users/me/my repo','/Users/me/w']}});
assert(ctx.viewerTest.agentPrompt(ctx.viewerTest.cur()).includes("`wpantry scan --path '~/my repo' --path ~/w --no-machine --licenses`"),'paths are quoted for the shell');
load(bundle);
search('smallvec');
assert(main().includes('class="fleet"') && main().includes('>Check out our other tools'),'the fleet callout is on screen');
const screenBefore=main();
events['printBtn:click']();
assert.equal(printCalls,1);
const printed=elements['print-report'].innerHTML;
assert.equal(wellFormed(printed),null,'print document');
assert.equal(areas(printed).length,kinds.length,'print lists every area, whatever the search');
assert(printed.includes('CVE-2019-15551'),'print opens every row');
assert(!printed.includes('<button') && !printed.includes('Copy agent prompt') && !printed.includes('class="jump"'));
assert(!printed.includes('class="fleet"'),'print leaves the callout out');
assert(printed.includes('Waffuru AI, Inc. is not liable') && printed.includes('Read the report before you hand it over.'),'print keeps the caution and the notice');
assert(printed.includes('Not checked') && printed.includes('CISA KEV') && text(printed).includes('sudo fdesetup enable') && printed.includes('Exposure log'));
assert.equal(main(),screenBefore,'print leaves the screen alone');
events['window:afterprint']();
assert.equal(elements['print-report'].innerHTML,'');
events['window:beforeprint']();
assert.equal(elements['print-report'].innerHTML,printed);
search('');
click({show:'warn'});
assert(!main().includes('<span class="comp">Slack</span>'));
click({show:'warn'});
click({kev:'1'});
assert.deepEqual(areas().map(x=>x[0]).sort(),['extension','project']);
click({kev:'1'});
search('nothing-matches-this');
assert(main().includes('Nothing matches these filters'));
search('');

// imports: a JSON report, a bundle, a CSV, and the formats that are not scans
const header='id,aliases,url,component,kind,affected_version,safe_version,severity,kev,status,location';
assert(ctx.viewerTest.validReport(ctx.viewerTest.csvToReport(ctx.viewerTest.parseCSV(header))));
assert(!ctx.viewerTest.validReport(ctx.viewerTest.csvToReport(ctx.viewerTest.parseCSV(header+'\nCVE-1,,,example,project,1,2,,false,bogus,loc'))));
const dependency={...every[4],dep_scope:'dev',dep_direct:false,affected_range:'>=1, <2'};
for(const bad of [{dep_direct:'false'},{dep_scope:{}},{affected_range:[]}])assert(!ctx.viewerTest.validReport({...report,findings:[{...dependency,...bad}]}));
ctx.viewerTest.addText(JSON.stringify({...report,findings:[dependency,{...every[9]},{...every[29]}]}),'imported.json');
assert(main().includes('imported.json') && main().includes('What this scan <em>found</em>'));
assert(main().includes('Not recorded in an imported report'),'scope of an import is unknown');
assert(!main().includes('/example/posture.txt'));
assert(section('patching').includes('Not recorded in an imported report; the history lives in the cache'));
assert(section('manual').includes('sudo fdesetup enable') && section('manual').includes('Grouped from the findings'));
assert(!main().includes('<section class="sec" id="history">'));
click({agentPrompt:'1'});
assert(copied.includes('a scope this report does not record: ask me') && !copied.includes('scan #42') && copied.includes('run the scan I tell you to first'),'an import records no scope');
const beforeInvalid=main();
ctx.viewerTest.addText('{"schema":1,"findings":[]}','invalid.json');
assert.equal(main(),beforeInvalid);
assert(elements.toast.textContent.includes('isn’t a Pantry JSON report'));
ctx.viewerTest.addText(JSON.stringify({schema:1,exposures:[],scans:[]}),'history.json');
assert.equal(main(),beforeInvalid,'a history report is not a scan');
ctx.viewerTest.addText(JSON.stringify({...dependency,schema:1,resolved_at:'2026-10-30'}),'history.jsonl');
assert.equal(main(),beforeInvalid,'a JSONL export is not a scan');
ctx.viewerTest.addText(header+'\nCVE-1,GHSA-1,,csv-package,project,1,2,HIGH,false,warn,loc','sample.csv');
assert(main().includes('csv-package') && main().includes('This scan came from a CSV export'));
assert(section('scanned').includes('CSV exports leave them out') && section('scanned').includes('cannot establish complete coverage'));
assert(section('manual').includes('CSV exports do not include suggested actions'));
click({open:'0'});
assert(main().includes('href="https://github.com/advisories/GHSA-1"'),'CSV aliases link');
click({agentPrompt:'1'});
assert(copied.includes('This came from a CSV export'));
assert(main().includes('class="run on"'),'several runs show a chooser');
click({run:'0'});
assert(main().includes('<b>erics-mac</b>'));
assert.equal(wellFormed(main()),null);

// nothing found is said carefully; the all-clear state needs complete, scoped evidence
load({...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,unfixed:0,unknown_licenses:0,findings:[]}}],plan:[],history:null,scope:{...scope,offline:true}});
assert(main().includes('No findings in this report') && !/clean result|no updates needed/i.test(main()));
assert(section('risk').includes('Nothing failed or warned in what was checked'));
assert(section('patching').includes('The local history could not be read'));
const cleanBundle={...bundle,phase:'after updates',plan:[],history:null,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,checked:{'git repos':1},unfixed:0,unknown_licenses:0,findings:[]}}]};
load(cleanBundle);
assert(main().includes('All clear. Nicely <em>done.</em>') && main().includes('The recheck found no findings'));
assert(main().includes('<img src="data:image/png;base64,AAAA" alt="">'));
events['window:beforeprint']();
assert(elements['print-report'].innerHTML.includes('All clear.'));
for(const [label,change] of [
  ['unfixed',{unfixed:1}],['unknown licenses',{unknown_licenses:1}],['empty inventory',{checked:{}}],
  ['zero inventory',{checked:{'git repos':0}}],['unchecked',{findings:[every[29]]}],
  ['warning',{findings:[every[13]]}],['failure',{findings:[every[4]]}]
]){
  load({...cleanBundle,runs:[{...cleanBundle.runs[0],report:{...cleanBundle.runs[0].report,...change}}]});
  assert(!main().includes('All clear.'),label);
}
for(const change of [{scope:null},{scope:{...scope,offline:true}},{phase:'after updates (an update command failed)'}]){
  load({...cleanBundle,...change});
  assert(!main().includes('All clear.'),JSON.stringify(change));
}
load({...cleanBundle,phase:'after updates (an update command failed)'});
assert(main().includes('An update command failed.'));
load(cleanBundle);
ctx.viewerTest.addText(JSON.stringify(cleanBundle.runs[0].report),'empty-import.json');
assert(!main().includes('All clear.'));
ctx.viewerTest.addText(header,'empty-export.csv');
assert(!main().includes('All clear.'));

// long lists are paged on screen (10 a page, 25/50/100 on request), complete in print
const many=[]; for(let i=0;i<60;i++)many.push(finding('brew','formula-'+i,'CVE-2026-'+(100+i),'fail',{severity:'HIGH',fixed:'2',fix_cmd:'sudo fix formula-'+i}));
load({...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,findings:many}}],plan:planOf(many),history:null});
const comps=src=>(src.match(/<span class="comp">([^<]*)<\/span>/g)||[]).map(x=>x.replace(/<[^>]+>/g,''));
let brew=areas()[0][1];
assert.deepEqual(comps(brew),many.slice(0,10).map(f=>f.component));
assert(brew.includes('1–10 of 60 components') && brew.includes('data-page="area:brew" data-to="1"') && brew.includes('data-size="area:brew" data-n="100"'));
assert(brew.includes('<button type="button" data-page="area:brew" data-to="0" aria-current="true"') && brew.includes('aria-label="Previous page">‹</button>'.replace('>‹<','>\u2039<')));
assert.equal((section('manual').match(/<li>/g)||[]).length,10);
assert(section('manual').includes('Needs you · 60 steps') && section('manual').includes('<ol class="steps" data-paged="manual" style="counter-reset:step 0">') && section('manual').includes('1–10 of 60 steps'));
click({page:'area:brew',to:'1'});
brew=areas()[0][1];
assert.deepEqual(comps(brew),many.slice(10,20).map(f=>f.component),'the second page');
assert(brew.includes('11–20 of 60 components'));
click({page:'manual',to:'2'});
assert(section('manual').includes('<ol class="steps" data-paged="manual" style="counter-reset:step 20">') && section('manual').includes('21–30 of 60 steps'),'step numbers continue across pages');
click({size:'area:brew',n:'100'});
brew=areas()[0][1];
assert.equal(comps(brew).length,60,'a page of 100 shows every component');
assert(brew.includes('1–60 of 60 components') && !brew.includes('data-page="area:brew"'),'one page: no page buttons');
assert.equal((section('manual').match(/<li>/g)||[]).length,60,'the chosen size becomes the default for the other lists');
click({size:'manual',n:'25'});
assert.equal((section('manual').match(/<li>/g)||[]).length,25);
assert.equal(comps(areas()[0][1]).length,60,'a size chosen for one list keeps the others as they were set');
search('formula-5');
assert(areas()[0][1].includes('1–11 of 11 components'),'a search starts again from the first page');
search('');
// an area folds to its header and back; print never folds
click({fold:'area:brew'});
brew=areas()[0][1];
assert(brew.includes('data-fold="area:brew" aria-expanded="false"') && comps(brew).length===0 && brew.includes('60 components'),'the header stays');
events['window:beforeprint']();
const printedMany=elements['print-report'].innerHTML;
assert.equal(comps(areas(printedMany)[0][1]).length,60,'print lists every component');
assert.equal((section('manual',printedMany).match(/<li>/g)||[]).length,60,'print lists every step');
assert(!printedMany.includes('class="pager"') && !printedMany.includes('data-fold'));
click({fold:'area:brew'});
assert.equal(comps(areas()[0][1]).length,60);
assert.equal(wellFormed(main()),null);
// counts read with thousands separators; the verdict names known exploits
const big=[]; for(let i=0;i<1200;i++)big.push(finding('brew','pkg-'+i,'CVE-2026-'+(10000+i),'fail',{severity:'HIGH',kev:i<1001,fixed:'2',fix_cmd:'brew upgrade pkg-'+i,fix_auto:true}));
load({...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,checked:{'project dependencies':203841},findings:big}}],plan:planOf(big),history:null});
assert(main().includes('<div class="v">203,841</div>') && main().includes('1,200 things to update') && main().includes('1,200 failing findings across 1,200 components, 0 warnings, 1,001 known exploits.'),main().split('class="verdict')[1].slice(0,300));
assert(areas()[0][1].includes('1,200 components') && areas()[0][1].includes('1–10 of 1,200 components'));
assert(section('patching').includes('<div class="big">1,200<small>commands</small></div>') && section('patching').includes('<ul class="long">') && !section('patching').includes('class="pager"'),'patching lists everything, scrolling, never paged');
assert(main().includes('A detailed summary of what was checked, what you are potentially exposed to, what can be patched, and how to do it. Results cover only what was checked and may not be exhaustive.'));
// a search opens the areas that match and shows the others folded
load(bundle);
click({fold:'area:project'});
assert(areas().find(x=>x[0]==='project')[1].includes('aria-expanded="false"'));
search('smallvec');
let proj=areas().find(x=>x[0]==='project')[1];
assert(proj.includes('aria-expanded="true"') && proj.includes('smallvec'),'a folded area with a match opens');
assert.equal(areas().filter(x=>x[1].includes('no match in')).length,areas().length-1,'the areas without a match stay as folded headers');
assert(!areas().some(x=>x[1].includes('nomatch') && x[1].includes('data-fold')),'a no-match header is not a control');
search('');
assert(areas().find(x=>x[0]==='project')[1].includes('aria-expanded="false"'),'the fold comes back once the search clears');
click({fold:'area:project'});
assert.equal(wellFormed(main()),null);
// the history logs fold too, and page
load({...bundle,history:{...history,exposures:Array.from({length:30},(_,i)=>({...history.exposures[0],component:'exp-'+i,resolved_at:1,resolved:'2026-10-30'}))}});
hist=section('history');
assert(hist.includes('1–10 of 30 exposures') && (hist.match(/<td>exp-/g)||[]).length===10);
click({fold:'exposures'});
hist=section('history');
assert(hist.includes('data-fold="exposures" aria-expanded="false"') && !hist.includes('<td>exp-') && hist.includes('Remediation log'));
events['window:beforeprint']();
assert.equal((section('history',elements['print-report'].innerHTML).match(/<td>exp-/g)||[]).length,30,'print has the whole log');
assert.equal(wellFormed(main()),null);
load(bundle);

// a bundle whose plan does not fit its findings is ignored, not trusted
load({...bundle,plan:[{command:'rm -rf /',mode:'auto',findings:[999]}]});
assert(!main().includes('rm -rf'));
assert(section('manual').includes('Grouped from the findings'));


// Risk: an area the user left out on purpose (`excluded`) counted as a coverage gap, so the page
// said "not checked: coverage is incomplete" about a scope the user chose. Oracle: the Rust rule
// Finding::is_gap(): an `unchecked` finding is a gap unless it is `excluded`. Known bad: count
// every `unchecked` finding (the page then says 2 things and lists the excluded area as one).
{
  const left=finding('unchecked','Personal documents and images','UNCHECKED','warn',{note:'Skipped by your choice (--no-personal-files). Include personal folders to check it.',excluded:true,location:'',version:''});
  const real=finding('unchecked','CISA KEV','UNREACHABLE','warn',{note:'offline and not cached',location:'',version:''});
  const run=(findings)=>({...bundle,plan:[],history:null,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,unfixed:0,unknown_licenses:0,findings}}]});
  load(run([left,real]));
  assert.equal(ctx.viewerTest.cur().counts.unchecked,1,'one gap, not two');
  const s=section('scanned');
  assert(s.includes('1 thing could not be checked') && !s.includes('2 things could not be checked'),'the gap count');
  assert(s.includes('<b>CISA KEV</b>') && !s.includes('<div class="gap"><span class="badge gap">Not checked</span><b>Personal documents and images</b>'),'only the real gap is listed as one');
  assert(s.includes('Left out by your choice, so not read: Personal documents and images.'),'the excluded area is said, as a scope');
  assert(main().includes('1 thing not checked: coverage is incomplete.'));
  assert.equal(wellFormed(main()),null);
  // Only an excluded area: no gap, no "incomplete" line, and the page does not say a source failed.
  load(run([left]));
  assert.equal(ctx.viewerTest.cur().counts.unchecked,0);
  assert(!/coverage is incomplete|could not be checked/.test(main()),'a chosen scope is not a gap');
  assert(section('scanned').includes('Every source answered: no coverage gaps were recorded for this scan.'));
  // An older report with no `excluded` key keeps every unchecked finding a gap.
  const old={...left}; delete old.excluded;
  load(run([old]));
  assert.equal(ctx.viewerTest.cur().counts.unchecked,1);
}


// A record from a folder of your own OSV records links what the record gives, or nothing: never OSV.dev.
// The source and the link are fields of the finding (local_source, local_link); the note is free text from an
// advisory and is never read for a link. Risk: an upstream summary that imitates the source marker
// re-points an advisory's link. Oracle: the href of each finding's id in the rendered page.
{
  const own='https://advisories.example.com/TEAM-2026-0001';
  const mine=[
    finding('project','acme-internal-widget','TEAM-2026-0001','fail',{fixed:'1.2.4',note:'key leak (from your source team-advisories: '+own+')',local_source:'team-advisories',local_link:own}),
    finding('project','acme-other','TEAM-2026-0002','fail',{fixed:'2.0.0',note:'other leak (from your source team-advisories)',local_source:'team-advisories',local_link:''}),
    finding('project','acme-third','GHSA-aaaa-bbbb-cccc','fail',{fixed:'3.0.0',note:'third leak (also in your source team-advisories)'}),
    // An upstream summary that looks like the marker, with no fields: the upstream advisory page, never this one.
    finding('project','acme-crafted','GHSA-dddd-eeee-ffff','fail',{fixed:'4.0.0',note:'crafted (from your source x: https://evil.example/a)'}),
    // The same text in a local finding whose fields say otherwise: the declared link wins.
    finding('project','acme-declared','TEAM-2026-0003','fail',{fixed:'5.0.0',note:'declared (from your source x: https://evil.example/b)',local_source:'team-advisories',local_link:'https://advisories.example.com/TEAM-2026-0003'}),
    // A link that is not https is not a link.
    finding('project','acme-http','TEAM-2026-0004','fail',{fixed:'6.0.0',local_source:'team-advisories',local_link:'http://insecure.example/TEAM-2026-0004'}),
    finding('project','acme-script','TEAM-2026-0005','fail',{fixed:'7.0.0',local_source:'team-advisories',local_link:'javascript:alert(1)'}),
    finding('project','acme-quote','TEAM-2026-0006','fail',{fixed:'8.0.0',local_source:'team-advisories',local_link:'https://advisories.example.com/x" onmouseover="alert(1)'}),
  ];
  load({...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,findings:mine}}],plan:[]});
  mine.forEach((f,i)=>click({open:String(i)}));
  const page=main();
  assert(page.includes('<a href="'+own+'"'),'the record’s own link');
  assert(!page.includes('osv.dev'),'no OSV.dev link for a record of your own');
  assert(!page.includes('href="https://advisories.example.com/TEAM-2026-0002'),'no link when the record gives none');
  assert(page.includes('href="https://github.com/advisories/GHSA-aaaa-bbbb-cccc"'),'a remote record keeps its link');
  assert(page.includes('href="https://github.com/advisories/GHSA-dddd-eeee-ffff"'),'a crafted summary does not change an upstream link');
  assert(!page.includes('href="https://evil.example'),'no link is read out of a note');
  assert(page.includes('href="https://advisories.example.com/TEAM-2026-0003"'),'a local finding links its declared link');
  assert(!/href="http:/.test(page)&&!page.includes('href="javascript:'),'a link that is not https is not a link');
  assert(!page.includes('onmouseover="alert'),'a link with a quote in it does not break out of the attribute');
  // The fields are checked as strings when a report is loaded.
  assert(ctx.viewerTest.validReport({...report,findings:[{...mine[0]}]}),'a finding with the fields is valid');
  assert(!ctx.viewerTest.validReport({...report,findings:[{...mine[0],local_link:5}]}),'a link that is not a string is refused');
  assert(ctx.viewerTest.validReport({...report,findings:[{...mine[2]}]}),'older findings without the fields still load');
}

/* ---------- the packed and deflated bundle src/reporters/pack.rs writes ---------- */
// pack-fixture.json is that module's output byte for byte (its Rust test
// checks), so the page decodes exactly what a report carries.
(async()=>{
  const fx=JSON.parse(fs.readFileSync(path.join(__dirname,'pack-fixture.json'),'utf8'));
  assert.deepStrictEqual(JSON.parse(JSON.stringify(ctx.viewerTest.unpack(fx.packed))),fx.bundle,'unpack gives back the bundle');
  assert.equal(ctx.viewerTest.unpack(bundle),bundle,'an unpacked bundle passes through');
  const shown=()=>{events['window:beforeprint'](); return main()+elements['print-report'].innerHTML}; // the screen and the whole print document
  load(fx.bundle); const plain=shown();
  assert(plain.includes('~/.npmrc') && plain.includes('GHSA-8g5g-mxqh-grgj') && plain.includes('<section class="sec" id="history">'),'the fixture renders its findings and history');
  load(fx.packed); assert.equal(shown(),plain,'a packed bundle renders as the plain one');
  Object.assign(ctx,{atob,Blob,Response,DecompressionStream});
  load({pantry_deflated:fx.deflated}); await ctx.viewerTest.ready;
  assert.equal(shown(),plain,'a deflated bundle renders as the plain one');
  // The fields a local finding links from survive the packer and the deflate: the same two findings, plain,
  // packed (rows and a string table, as pack.rs writes them) and deflated (node's zlib stands in for the
  // writer), give the same links. Oracle: the hrefs in the rendered page.
  {
    const own='https://advisories.example.com/TEAM-2026-0001';
    const two=[
      finding('project','acme-internal-widget','TEAM-2026-0001','fail',{fixed:'1.2.4',local_source:'team-advisories',local_link:own}),
      finding('project','acme-crafted','GHSA-dddd-eeee-ffff','fail',{fixed:'4.0.0',note:'crafted (from your source x: https://evil.example/a)',local_source:'',local_link:''}),
    ];
    const data={...bundle,runs:[{title:'Security scan',file:'wpantry scan',report:{...report,findings:two}}],plan:[]};
    const keys=Object.keys(two[0]);
    const rows=two.map(f=>keys.map(k=>f[k]===own?'~0':f[k]));
    const packed={pantry_packed:1,strings:[own],data:{...data,runs:[{...data.runs[0],report:{...report,findings:['~',keys,...rows]}}]}};
    const links=()=>{two.forEach((f,i)=>click({open:String(i)}));return main()};
    const check=(page,how)=>{
      assert(page.includes('<a href="'+own+'"'),how+': the declared link');
      assert(page.includes('href="https://github.com/advisories/GHSA-dddd-eeee-ffff"'),how+': a crafted summary keeps the advisory page');
      assert(!page.includes('href="https://evil.example'),how+': no link out of a note');
    };
    load(data); check(links(),'plain');
    load(packed); check(links(),'packed');
    load({pantry_deflated:require('zlib').deflateRawSync(JSON.stringify(packed)).toString('base64')}); await ctx.viewerTest.ready; check(links(),'deflated');
  }
  load({pantry_deflated:fx.deflated.slice(0,40)}); await ctx.viewerTest.ready;
  assert(main().includes('is compressed'),'a corrupt stream says so');
  // Risk: a fault in the page (start, unpack or render throwing) is reported
  // as "your browser cannot unpack this report". Oracle: with a good stream
  // and a render that throws, the error surfaces and that message is never set.
  {
    const m=el('main'), sets=[]; let first=true;
    Object.defineProperty(m,'innerHTML',{configurable:true,enumerable:true,get(){return sets[sets.length-1]||''},set(v){if(first){first=false;throw new Error('render broke')} sets.push(v)}});
    load({pantry_deflated:fx.deflated});
    await ctx.viewerTest.ready.then(()=>assert.fail('a render error must not be swallowed'),e=>assert.equal(e.message,'render broke'));
    assert(!sets.some(s=>s.includes('is compressed')),'a render error is not blamed on the compressed stream');
    Object.defineProperty(m,'innerHTML',{value:'',writable:true,configurable:true,enumerable:true});
  }
  delete ctx.DecompressionStream;
  load({pantry_deflated:fx.deflated}); await ctx.viewerTest.ready;
  assert(main().includes('is compressed') && main().includes('wpantry report --json'),'a browser without DecompressionStream says what to do');
  console.log('viewer: every kind under its area in fix order, gaps as gaps, the plan by hand and unattended, history, escaping, imports, print, the all-clear state and packed and deflated bundles passed');
})().catch(e=>{console.error(e);process.exitCode=1});
