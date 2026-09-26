export const TOOL_ID='deployment-health-gate';
export const LIMITS=Object.freeze({policyBytes:65536,captureBytes:1048576,metrics:100,samples:10000,depth:16,milliseconds:5000});
const SEVERITY=Object.freeze({'input-unreadable':'warning','input-invalid':'warning','export-incomplete':'warning','byte-limit':'warning','record-limit':'warning','depth-limit':'warning','time-limit':'warning','sample-invalid':'warning','sample-duplicate':'warning','future-sample':'warning','metric-missing':'warning','samples-insufficient':'warning','no-data':'warning','no-data-block':'error','threshold-exceeded':'error'});
const MESSAGE=Object.freeze({'input-unreadable':'Input could not be read, decoded, or parsed.','input-invalid':'Policy or capture structure is invalid.','export-incomplete':'Capture does not assert complete coverage.','byte-limit':'Input exceeds its declared byte limit.','record-limit':'Metric or sample count exceeds its limit.','depth-limit':'JSON nesting exceeds depth 16.','time-limit':'Evaluation exceeded 5000 milliseconds.','sample-invalid':'Sample has unusable time or value evidence.','sample-duplicate':'Sample identity is duplicated.','future-sample':'Sample occurs after capture cutoff.','metric-missing':'Required metric is absent from an in-window sample.','samples-insufficient':'Required metric has fewer than the minimum samples.','no-data':'No in-window required health data was captured.','no-data-block':'No in-window required health data was captured; policy blocks.','threshold-exceeded':'Required health metric exceeded its threshold.'});
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const safe=x=>typeof x==='string'&&x.length>0&&x.length<=128&&/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(x);
const keysOnly=(x,keys)=>Object.keys(x).every(k=>keys.includes(k));
function finding(ruleId,file,pointer=''){return {ruleId,severity:SEVERITY[ruleId],message:MESSAGE[ruleId],location:{file,pointer}};}
function report(findings,checked=0){findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));const status=findings.some(x=>x.severity==='warning')?'incomplete':findings.some(x=>x.severity==='error')?'fail':'pass';return {schemaVersion:'1',tool:TOOL_ID,status,decision:status==='pass'?'allow':status==='fail'?'block':'unknown',summary:{checked,errors:findings.filter(x=>x.severity==='error').length,warnings:findings.filter(x=>x.severity==='warning').length},findings};}
export function incomplete(ruleId,file){return report([finding(ruleId,file)]);}
function tooDeep(value){const stack=[[value,0]];while(stack.length){const [item,depth]=stack.pop();if(depth>LIMITS.depth)return true;if(item&&typeof item==='object')for(const child of Object.values(item))stack.push([child,depth+1]);}return false;}
function instant(text){
  if(typeof text!=='string')return null;
  const m=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/.exec(text);if(!m)return null;
  const [y,mo,d,h,mi,s,ms]=m.slice(1,8).map((v,i)=>i===6?Number((v??'0').padEnd(3,'0')):Number(v));
  if(mo<1||mo>12||d<1||d>31||h>23||mi>59||s>59)return null;
  const date=new Date(0);date.setUTCFullYear(y,mo-1,d);date.setUTCHours(h,mi,s,ms);
  if(date.getUTCFullYear()!==y||date.getUTCMonth()!==mo-1||date.getUTCDate()!==d)return null;
  let offset=0;if(m[8]!=='Z'){const oh=Number(m[8].slice(1,3)),om=Number(m[8].slice(4));if(oh>23||om>59)return null;offset=(oh*60+om)*60000*(m[8][0]==='+'?1:-1);}
  return date.getTime()-offset;
}
export function evaluateHealth(policy,capture,{now=()=>performance.now()}={}){
  const start=now(),timed=()=>now()-start>LIMITS.milliseconds,findings=[];
  if(tooDeep(policy))findings.push(finding('depth-limit','@policy'));
  if(tooDeep(capture))findings.push(finding('depth-limit','@capture'));
  if(findings.length)return report(findings);
  if(!object(policy)||!keysOnly(policy,['schemaVersion','policyVersion','observationWindowMs','minSamples','noData','requiredMetrics','metadata'])||policy.schemaVersion!=='1'||!safe(policy.policyVersion)||!Number.isInteger(policy.observationWindowMs)||policy.observationWindowMs<1000||policy.observationWindowMs>86400000||!Number.isInteger(policy.minSamples)||policy.minSamples<1||policy.minSamples>LIMITS.samples||!['incomplete','fail'].includes(policy.noData)||!Array.isArray(policy.requiredMetrics)||policy.requiredMetrics.length===0){findings.push(finding('input-invalid','@policy'));return report(findings);}
  if(policy.requiredMetrics.length>LIMITS.metrics){findings.push(finding('record-limit','@policy','/requiredMetrics'));return report(findings);}
  const names=new Set();
  for(const [i,item] of policy.requiredMetrics.entries()){
    if(!object(item)||!keysOnly(item,['name','max'])||!safe(item.name)||!Number.isFinite(item.max)||item.max<0||item.max>1e12||names.has(item.name)){findings.push(finding('input-invalid','@policy',`/requiredMetrics/${i}`));continue;}names.add(item.name);
  }
  if(findings.length)return report(findings);
  if(!object(capture)||!keysOnly(capture,['schemaVersion','complete','observedAt','samples','metadata'])||capture.schemaVersion!=='1'||!Array.isArray(capture.samples)||instant(capture.observedAt)===null){findings.push(finding('input-invalid','@capture'));return report(findings);}
  if(capture.complete!==true){findings.push(finding('export-incomplete','@capture','/complete'));return report(findings);}
  if(capture.samples.length>LIMITS.samples){findings.push(finding('record-limit','@capture','/samples'));return report(findings);}
  const cutoff=instant(capture.observedAt),startWindow=cutoff-policy.observationWindowMs,ids=new Set(),counts=new Map([...names].map(x=>[x,0]));let checked=0;
  for(const [i,item] of capture.samples.entries()){
    if(timed())return incomplete('time-limit','@capture');
    const pointer=`/samples/${i}`,at=object(item)?instant(item.at):null;
    if(!object(item)||!keysOnly(item,['id','at','metrics'])||!safe(item.id)||at===null||!object(item.metrics)||Object.entries(item.metrics).some(([k,v])=>!safe(k)||!Number.isFinite(v)||v<0)){findings.push(finding('sample-invalid','@capture',pointer));continue;}
    if(ids.has(item.id))findings.push(finding('sample-duplicate','@capture',`${pointer}/id`));else ids.add(item.id);
    if(at>cutoff){findings.push(finding('future-sample','@capture',`${pointer}/at`));continue;}
    if(at<startWindow)continue;
    checked++;
    for(const [j,metric] of policy.requiredMetrics.entries()){
      const value=item.metrics[metric.name];
      if(!Object.hasOwn(item.metrics,metric.name)){findings.push(finding('metric-missing','@capture',`${pointer}/metrics`));continue;}
      counts.set(metric.name,counts.get(metric.name)+1);
      if(value>metric.max)findings.push(finding('threshold-exceeded','@capture',`${pointer}/metrics`));
    }
  }
  if(timed())return incomplete('time-limit','@capture');
  if(checked===0)findings.push(finding(policy.noData==='fail'?'no-data-block':'no-data','@capture','/samples'));
  else for(const [j,item] of policy.requiredMetrics.entries())if(counts.get(item.name)<policy.minSamples)findings.push(finding('samples-insufficient','@capture','/samples'));
  return report(findings,checked);
}
