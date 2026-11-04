'use strict';
const get = id => document.getElementById(id);
const runId = () => encodeURIComponent(get('runId').value.trim());
const source = () => get('source').value;
const request = () => ({action_id:'process.spawn_benign', scenario_id:get('scenarioId').value.trim(), action_parameters:{profile:get('profile').value}});
async function call(path, method='GET', body, execution=false, text=false) {
  const token = get(execution?'executionToken':'apiToken').value;
  const headers = {'Content-Type':'application/json'};
  if(token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
  if(!response.ok) throw new Error(`${response.status}: ${await response.text()}`);
  return text?response.text():response.json();
}
function download(value,name,type='application/json') {
  const url=URL.createObjectURL(new Blob([typeof value==='string'?value:JSON.stringify(value,null,2)],{type}));
  const link=document.createElement('a'); link.href=url; link.download=name; link.click(); URL.revokeObjectURL(url);
}
function bind(id, action) {get(id).addEventListener('click',async()=>{get('state').textContent='Working…';get(id).disabled=true;try{const data=await action();get('output').textContent=JSON.stringify(data,null,2);get('state').textContent='Complete';}catch(error){get('output').textContent=error.message;get('state').textContent='Failed';}finally{get(id).disabled=false;}});}
bind('status',()=>call(`/api/v1/${source()}/status`));
bind('refresh',async()=>({scenarios:await call('/api/v1/scenarios'),runs:await call('/api/v1/runs')}));
bind('clear',()=>{get('apiToken').value='';get('executionToken').value='';return {tokens:'cleared'};});
bind('createScenario',()=>call('/api/v1/scenarios','POST',JSON.parse(get('scenario').value)));
bind('createRule',()=>call('/api/v1/rules','POST',JSON.parse(get('rule').value)));
bind('actions',()=>call('/api/v1/execution/actions','GET',undefined,true));
bind('validate',()=>call('/api/v1/execution/validate','POST',request(),true));
bind('execute',async()=>{const data=await call('/api/v1/execution/run','POST',request(),true);get('runId').value=data.test_run_id||'';get('executionId').value=data.execution_id;return data;});
bind('groundTruth',()=>call('/api/v1/ground-truth','POST',{ground_truth_id:`GT-${get('runId').value}`,run_id:get('runId').value,expected_diagnostic_category:get('label').value,verification_method:get('verification').value,verification_evidence:get('verificationEvidence').value,label_status:'confirmed'}));
bind('collect',()=>call(`/api/v1/${source()}/assurance/${runId()}?strict_attribution=true`,'POST'));
bind('evaluate',()=>call(`/api/v1/evaluation/${runId()}?strict_attribution=true`,'POST'));
bind('explain',()=>call(`/api/v1/explanations/${runId()}`,'POST'));
bind('report',()=>call(`/api/v1/reports/runs/${runId()}`));
bind('export',async()=>{const data=await call(`/api/v1/reports/runs/${runId()}`);download(data,'proofshield-evidence.json');return data;});
bind('csv',async()=>{const data=await call(`/api/v1/reports/runs/${runId()}/export.csv`,'GET',undefined,false,true);download(data,'proofshield-report.csv','text/csv');return {downloaded:true};});
bind('evidence',()=>call(`/api/v1/reports/runs/${runId()}`));
bind('history',async()=>({active:await call('/api/v1/execution/active','GET',undefined,true),records:await call('/api/v1/execution/records','GET',undefined,true)}));
bind('cancel',()=>call(`/api/v1/execution/records/${encodeURIComponent(get('executionId').value)}/cancel`,'POST',undefined,true));
bind('dataset',async()=>{const data=await call('/api/v1/research/dataset?include_synthetic='+get('synthetic').checked);download(data,'proofshield-dataset.json');return data;});
bind('research',()=>call('/api/v1/research/evaluate?include_synthetic='+get('synthetic').checked,'POST'));
