// Public, non-production test-only values. No secret contents are logged.
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
globalThis.crypto ??= webcrypto;
const { WasmVault } = require('../pkg/rust_vault.js');
const b = s => new TextEncoder().encode(s);
const route = {action:3,kind:2,source_route_id:new Uint8Array(),credential_id:b('public-test-credential'),protection:0};
const create = {tag:1,payload:{target_id:b('t'),purposes:[{plan:{purpose_id:b('a'),routes:[route]},plaintext:b('public payload')}]}};
async function finish(v, s, recovery, password) {
  while (s.tag === 2) {
    const r=s.payload.requests[0];
    assert.equal(typeof r.operation_id,'bigint');assert.equal(typeof r.request_id,'bigint');
    const payload=r.kind===1?{password}:r.kind===3?{prf_output:new Uint8Array(32).fill(0x51)}:{recovery_key:recovery};
    s=await v.resume(r.operation_id,r.request_id,{kind:r.kind,status:0,payload});
  }
  return s.payload.payload;
}
(async()=>{
  assert.throws(()=>new WasmVault(134217728),e=>e===1);
  const v=new WasmVault(134217728n);
  const c=await finish(v,await v.begin(create));
  assert(c.snapshot instanceof Uint8Array);assert(c.recovery_key instanceof Uint8Array);
  assert.equal(typeof c.candidate_id,'bigint');
  await v.confirm_saved(c.candidate_id,c.new_hash);
  const pending=await v.begin(create);const r=pending.payload.requests[0];
  await assert.rejects(v.resume(r.operation_id,r.request_id+1n,{kind:3,status:0,payload:{prf_output:new Uint8Array(32)}}),e=>e===8);
  await v.cancel(r.operation_id);
  await assert.rejects(v.resume(r.operation_id,r.request_id,{kind:3,status:0,payload:{prf_output:new Uint8Array(32)}}),e=>e===8);
  await assert.rejects(v.begin({...create,payload:{...create.payload,target_id:[1]}}),e=>e===1);
  const os={...create,payload:{...create.payload,purposes:[{plan:{purpose_id:b('a'),routes:[{...route,kind:4,credential_id:new Uint8Array(),protection:1}]},plaintext:b('p')} ]}};
  await assert.rejects(v.begin(os),e=>e===2);
  const fs=require('node:fs'), path=require('node:path');
  const vectors=Object.fromEntries(fs.readFileSync(path.join(__dirname,'fixtures/v1.txt'),'utf8').trim().split('\n').filter(l=>!l.startsWith('#')).map(l=>{const [k,h]=l.split('=');return [k,new Uint8Array(Buffer.from(h,'hex'))];}));
  const context={target_id:b('public-test-target'),purpose_id:b('public-test-purpose'),generation:1n};
  const selected={tag:11,payload:{selection:[{context,data:vectors.data,recovery_wrap:vectors.recovery_wrap}],lifetime:1}};
  const recovered=await finish(v,await v.begin(selected),vectors.recovery);
  const handle=recovered.recovered[0].context_handle;
  const dec={tag:5,payload:{context_handle:handle,context,data:vectors.data}};
  const plaintext=await finish(v,await v.begin(dec));assert.deepEqual(plaintext.plaintext,vectors.plaintext);
  await assert.rejects(v.begin(dec),e=>e===8);
  await assert.rejects(v.begin({...selected,payload:{...selected.payload,selection:[{...selected.payload.selection[0],context:{...context,generation:1}}]}}),e=>e===1);
  const unlock={tag:4,payload:{context,data:vectors.data,wrap:vectors.password_wrap,lifetime:1}};
  const unlocked=await finish(v,await v.begin(unlock),undefined,vectors.password);
  const fromPassword=await finish(v,await v.begin({tag:5,payload:{context_handle:unlocked.context_handle,context,data:vectors.data}}));
  assert.deepEqual(fromPassword.plaintext,vectors.plaintext);
  await v.destroy();v.free();
  console.log('PASS: WASM Promise / Uint8Array / bigint / PRF / Password vector / cancellation / OS isolation');
})().catch(e=>{console.error('WASM boundary test failed:',typeof e==='number'?e:e.message);process.exitCode=1;});
