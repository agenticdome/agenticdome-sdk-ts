import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import AgenticDomeClient from '../index';

describe('optional managed agent identity',()=>{
 const original={...process.env};
 afterEach(()=>{process.env={...original};});
 test('retains legacy authentication when identity is not configured',()=>{
  for(const name of Object.keys(process.env))if(name.startsWith('AGENTICDOME_'))delete process.env[name];
  const client=new AgenticDomeClient('https://runtime.example.test',{apiKey:'runtime-key',tenantId:'tenant-a'});
  const headers=(client as any).headers();expect(headers['X-API-Key']).toBe('runtime-key');expect(Object.keys(headers).some(k=>k.startsWith('X-AgenticDome-'))).toBe(false);client.close();
 });
 test('reads projected proof again after renewal and rejects ambiguous values',()=>{
  const dir=mkdtempSync(join(tmpdir(),'ad-identity-'));const file=join(dir,'token');
  const client=new AgenticDomeClient('https://runtime.example.test',{apiKey:'runtime-key',tenantId:'tenant-a'});
  try{process.env.AGENTICDOME_IDENTITY_DEPLOYMENT='approved-deployment';process.env.AGENTICDOME_WORKLOAD_TOKEN_FILE=file;
   writeFileSync(file,'first-proof\n');expect((client as any).headers()['X-AgenticDome-Workload-Token']).toBe('first-proof');
   writeFileSync(file,'renewed-proof\n');expect((client as any).headers()['X-AgenticDome-Workload-Token']).toBe('renewed-proof');
   process.env.AGENTICDOME_WORKLOAD_TOKEN='ambiguous';expect(()=>(client as any).headers()).toThrow('one identity');
  }finally{client.close();rmSync(dir,{recursive:true,force:true});}
 });
 test('identity methods preserve native IDs and use the assigned sidecar',async()=>{
  const client=new AgenticDomeClient('https://runtime.example.test',{apiKey:'runtime-key',tenantId:'tenant-a'});
  const request=jest.fn().mockResolvedValue({access_token:'scoped-token'});(client as any).request=request;
  await client.enrolIdentity('research-agent','crewai');await client.delegateIdentity('specialist','case-42');await client.exchangeIdentity('enrolled-token','approved-receiver','case-42','cases:read');
  expect(request.mock.calls.map(c=>c[1])).toEqual(['/identity/v1/enrol','/identity/v1/delegate','/identity/v1/token']);
  expect(request.mock.calls[0][2].jsonBody).toEqual({agent_id:'research-agent',framework:'crewai'});client.close();
 });
 test('existing hooks enrol once and send only the cached agent token for policy checks',async()=>{
  process.env.AGENTICDOME_IDENTITY_DEPLOYMENT='approved-deployment';process.env.AGENTICDOME_AGENT_CREDENTIAL='deployment-secret';
  const client=new AgenticDomeClient('https://runtime.example.test',{apiKey:'runtime-key',tenantId:'tenant-a'});
  const send=jest.fn().mockImplementation(async request=>({status:200,data:request.url==='/identity/v1/enrol'?{access_token:'verified-agent-token',expires_in:900}:{verdict:'ALLOWED'}}));(client as any).api.request=send;
  try{await client.guardrailValidate({text:'read case',agentId:'support',platform:'langgraph'});await client.guardrailValidate({text:'read case',agentId:'support',platform:'langgraph'});
   expect(send).toHaveBeenCalledTimes(3);expect(send.mock.calls[0][0].data).toEqual({agent_id:'support',framework:'langgraph'});
   for(const call of send.mock.calls.slice(1)){expect(call[0].headers['X-AgenticDome-Agent-Token']).toBe('verified-agent-token');expect(call[0].headers['X-AgenticDome-Agent-Credential']).toBeUndefined();}
  }finally{client.close();}
 });
 test('an old runtime cannot silently fall back to tenant-key-only protection',async()=>{
  process.env.AGENTICDOME_IDENTITY_DEPLOYMENT='approved-deployment';process.env.AGENTICDOME_AGENT_CREDENTIAL='deployment-secret';
  const client=new AgenticDomeClient('https://runtime.example.test',{apiKey:'runtime-key',tenantId:'tenant-a'});
  const send=jest.fn().mockResolvedValue({status:404,data:{}});(client as any).api.request=send;
  try{await expect(client.guardrailValidate({text:'read case',agentId:'support',platform:'langgraph'})).rejects.toThrow('Managed identity');expect(send).toHaveBeenCalledTimes(1);expect(send.mock.calls[0][0].url).toBe('/identity/v1/enrol');}finally{client.close();}
 });
 test('concurrent delegated tasks keep distinct identities and restore context',async()=>{
  delete process.env.AGENTICDOME_DELEGATION_TOKEN;delete process.env.AGENTICDOME_USER_TOKEN;delete process.env.AGENTICDOME_TASK_ID;
  const client=new AgenticDomeClient('https://runtime.example.test',{apiKey:'runtime-key',tenantId:'tenant-a'});
  const task=(token:string,id:string)=>client.withIdentity({delegationToken:token,taskId:id},async()=>{await Promise.resolve();return(client as any).headers();});
  try{const [first,second]=await Promise.all([task('first-delegation','case-1'),task('second-delegation','case-2')]);expect(first['X-AgenticDome-Delegation-Token']).toBe('first-delegation');expect(second['X-AgenticDome-Task-Id']).toBe('case-2');expect((client as any).headers()['X-AgenticDome-Delegation-Token']).toBeUndefined();}finally{client.close();}
 });
});
