import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {evaluateHealth,TOOL_ID,LIMITS} from '../src/index.mjs';
const policy=()=>({schemaVersion:'1',policyVersion:'v1',observationWindowMs:60000,minSamples:2,noData:'incomplete',requiredMetrics:[{name:'error_rate',max:0.02}]});
const capture=()=>({schemaVersion:'1',complete:true,observedAt:'2026-09-25T10:00:00Z',samples:[{id:'s1',at:'2026-09-25T09:59:00Z',metrics:{error_rate:0.01}},{id:'s2',at:'2026-09-25T10:00:00+00:00',metrics:{error_rate:0.015}}]});
test('complete healthy window permits rollout decision without deploying',()=>{
  const r=evaluateHealth(policy(),capture(),{now:()=>0});assert.equal(TOOL_ID,'deployment-health-gate');assert.equal(r.status,'pass');assert.equal(r.decision,'allow');assert.equal(r.summary.checked,2);assert.deepEqual(r.findings,[]);
});
test('bad required sample blocks, missing required metric remains unknown',()=>{
  const d=capture();d.samples[1].metrics.error_rate=0.03;let r=evaluateHealth(policy(),d,{now:()=>0});assert.equal(r.status,'fail');assert.equal(r.decision,'block');assert.equal(r.findings[0].ruleId,'threshold-exceeded');
  delete d.samples[1].metrics.error_rate;r=evaluateHealth(policy(),d,{now:()=>0});assert.equal(r.status,'incomplete');assert.equal(r.decision,'unknown');assert.ok(r.findings.some(x=>x.ruleId==='metric-missing'));
});
test('no-data policy explicitly chooses incomplete or fail, never pass',()=>{
  const d=capture();d.samples=[];let r=evaluateHealth(policy(),d,{now:()=>0});assert.equal(r.status,'incomplete');assert.equal(r.findings[0].ruleId,'no-data');const p=policy();p.noData='fail';r=evaluateHealth(p,d,{now:()=>0});assert.equal(r.status,'fail');assert.equal(r.decision,'block');
});
test('sample at window start counts, one millisecond older does not; offset instant matches UTC',()=>{
  const p=policy(),d=capture();assert.equal(evaluateHealth(p,d,{now:()=>0}).status,'pass');d.samples[0].at='2026-09-25T09:58:59.999Z';assert.equal(evaluateHealth(p,d,{now:()=>0}).status,'incomplete');d.samples[0].at='2026-09-25T11:59:00+02:00';assert.equal(evaluateHealth(p,d,{now:()=>0}).status,'pass');
});
test('partial capture, duplicate sample ID, future sample, and malformed timestamp cannot pass',()=>{
  const d=capture();d.complete=false;assert.equal(evaluateHealth(policy(),d,{now:()=>0}).status,'incomplete');d.complete=true;d.samples[1].id='s1';assert.equal(evaluateHealth(policy(),d,{now:()=>0}).status,'incomplete');d.samples[1].id='s2';d.samples[1].at='2026-09-25T10:00:00.001Z';assert.equal(evaluateHealth(policy(),d,{now:()=>0}).status,'incomplete');d.samples[1].at='2026-09-25T10:00:00';assert.equal(evaluateHealth(policy(),d,{now:()=>0}).status,'incomplete');
});
test('metric and sample N/N+1, depth, deadline',()=>{
  const p=policy(),d=capture();p.requiredMetrics=Array.from({length:LIMITS.metrics},(_,i)=>({name:`m${i}`,max:1}));for(const s of d.samples)s.metrics=Object.fromEntries(p.requiredMetrics.map(x=>[x.name,0]));assert.equal(evaluateHealth(p,d,{now:()=>0}).status,'pass');p.requiredMetrics.push({name:'extra',max:1});assert.equal(evaluateHealth(p,d,{now:()=>0}).findings[0].ruleId,'record-limit');
  const q=capture(),a=policy();q.samples=Array.from({length:LIMITS.samples},(_,i)=>({id:`s${i}`,at:'2026-09-25T10:00:00Z',metrics:{error_rate:0}}));assert.equal(evaluateHealth(a,q,{now:()=>0}).status,'pass');q.samples.push({id:'extra',at:'2026-09-25T10:00:00Z',metrics:{error_rate:0}});assert.equal(evaluateHealth(a,q,{now:()=>0}).findings[0].ruleId,'record-limit');
  const b=capture();b.metadata={};let x=b.metadata;for(let i=1;i<LIMITS.depth;i++){x.next={};x=x.next;}assert.equal(evaluateHealth(policy(),b,{now:()=>0}).status,'pass');x.next={};assert.equal(evaluateHealth(policy(),b,{now:()=>0}).findings[0].ruleId,'depth-limit');
  const clock=n=>{let first=true;return()=>{if(first){first=false;return 0;}return n;};};assert.equal(evaluateHealth(policy(),capture(),{now:clock(5000)}).status,'pass');assert.equal(evaluateHealth(policy(),capture(),{now:clock(5001)}).findings[0].ruleId,'time-limit');
});
test('policy depth and minimum-sample range accept N and refuse N+1',()=>{
  const p=policy();p.minSamples=LIMITS.samples;assert.equal(evaluateHealth(p,capture(),{now:()=>0}).findings[0].ruleId,'samples-insufficient');p.minSamples++;assert.equal(evaluateHealth(p,capture(),{now:()=>0}).findings[0].ruleId,'input-invalid');
  const q=policy();q.metadata={};let x=q.metadata;for(let i=1;i<LIMITS.depth;i++){x.next={};x=x.next;}assert.equal(evaluateHealth(q,capture(),{now:()=>0}).status,'pass');x.next={};assert.equal(evaluateHealth(q,capture(),{now:()=>0}).findings[0].ruleId,'depth-limit');
});
const cli=args=>spawnSync(process.execPath,['bin/deployment-health-gate.mjs',...args],{cwd:path.resolve(import.meta.dirname,'..'),encoding:'utf8'});
const fixture=run=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'health-gate-'));try{return run(root);}finally{fs.rmSync(root,{recursive:true,force:true});}};
test('CLI config/evidence split, duplicate keys, strict UTF-8, and confinement',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'policy.json'),JSON.stringify(policy()));fs.writeFileSync(path.join(root,'capture.json'),JSON.stringify(capture()));let r=cli(['--root',root,'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,0);assert.equal(JSON.parse(r.stdout).decision,'allow');
  fs.writeFileSync(path.join(root,'capture.json'),'{"schemaVersion":"1","complete":false,"compl\\u0065te":true,"samples":[]}');r=cli(['--root',root,'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
  fs.writeFileSync(path.join(root,'policy.json'),'{"schemaVersion":"1","noData":"fail","noData":"incomplete"}');r=cli(['--root',root,'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,2);assert.equal(r.stdout,'');fs.writeFileSync(path.join(root,'policy.json'),JSON.stringify(policy()));
  fs.writeFileSync(path.join(root,'capture.json'),Buffer.from([0xff]));r=cli(['--root',root,'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');
  const out=fs.mkdtempSync(path.join(os.tmpdir(),'health-out-'));try{fs.writeFileSync(path.join(out,'c.json'),JSON.stringify(capture()));fs.symlinkSync(path.join(out,'c.json'),path.join(root,'escape.json'));r=cli(['--root',root,'--policy','policy.json','--capture','escape.json']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).status,'incomplete');}finally{fs.rmSync(out,{recursive:true,force:true});}
}));
test('CLI byte bounds accept N and refuse N+1; invalid root has empty stdout',()=>fixture(root=>{
  fs.writeFileSync(path.join(root,'policy.json'),JSON.stringify(policy()));fs.writeFileSync(path.join(root,'capture.json'),JSON.stringify(capture()));
  for(const [name,limit] of [['policy.json',LIMITS.policyBytes],['capture.json',LIMITS.captureBytes]]){
    const raw=JSON.stringify(name==='policy.json'?policy():capture());fs.writeFileSync(path.join(root,name),raw+' '.repeat(limit-Buffer.byteLength(raw)));
    let r=cli(['--root',root,'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,0,name);
    fs.appendFileSync(path.join(root,name),' ');r=cli(['--root',root,'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,2);assert.equal(name==='policy.json'?r.stdout:JSON.parse(r.stdout).findings[0].ruleId,name==='policy.json'?'':'byte-limit');fs.writeFileSync(path.join(root,name),raw);
  }
  const r=cli(['--root',path.join(root,'missing'),'--policy','policy.json','--capture','capture.json']);assert.equal(r.status,2);assert.equal(r.stdout,'');
}));
