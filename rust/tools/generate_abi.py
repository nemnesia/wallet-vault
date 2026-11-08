"""Generate matching C/Rust declarations from the specification field tables."""
from pathlib import Path
root=Path(__file__).resolve().parents[1]
structs={
'VaultOptions':[('memory_budget_bytes','u64')],
'Bytes':[('ptr','*const u8'),('len','u32')],
'Context':[('target_id','Bytes'),('purpose_id','Bytes'),('generation','u64')],
'PurposeExpectation':[('purpose_id','Bytes'),('generation','u64')],
'ExpectedSnapshot':[('target_id','Bytes'),('purposes','*const PurposeExpectation'),('purpose_count','u32')],
'Source':[('snapshot','Bytes'),('expected','ExpectedSnapshot')],
'UnlockRoute':[('purpose_id','Bytes'),('route_id','Bytes')],
'RoutePlan':[('action','u32'),('kind','u32'),('source_route_id','Bytes'),('credential_id','Bytes'),('protection','u32')],
'PurposePlan':[('purpose_id','Bytes'),('routes','*const RoutePlan'),('route_count','u32')],
'PurposeInput':[('plan','PurposePlan'),('plaintext','Bytes')],
'SelectionInput':[('context','Context'),('data','Bytes'),('recovery_wrap','Bytes')],
'SelectionResultItem':[('context','Context'),('context_handle','u64')],
}
def array(t):return [('items','*const '+t),('count','u32')]
for t in ['Bytes','PurposeInput','PurposePlan','UnlockRoute','SelectionInput','SelectionResultItem']:
 structs[t+'Array']=array(t)
requests={
'Create':[('target_id','Bytes'),('purposes','PurposeInputArray')],
'AddPurpose':[('source','Source'),('purpose','PurposeInput')],
'RemovePurpose':[('source','Source'),('purpose_ids','BytesArray')],
'Unlock':[('context','Context'),('data','Bytes'),('wrap','Bytes'),('lifetime','u32')],
'Decrypt':[('context_handle','u64'),('context','Context'),('data','Bytes')],
'ReplaceData':[('source','Source'),('context_handle','u64'),('purpose_id','Bytes'),('plaintext','Bytes')],
'Rewrap':[('source','Source'),('plans','PurposePlanArray'),('fresh_unlock_routes','UnlockRouteArray')],
'RotateDek':[('source','Source'),('plans','PurposePlanArray'),('fresh_unlock_routes','UnlockRouteArray')],
'Recover':[('source','Source'),('plans','PurposePlanArray')],
'ReissueRecovery':[('source','Source'),('fresh_unlock_routes','UnlockRouteArray')],
'RecoverSelected':[('selection','SelectionInputArray'),('lifetime','u32')],
}
structs.update({k+'Request':v for k,v in requests.items()})
structs['UnlockResult']=[('context_handle','u64')]
structs['DecryptResult']=[('plaintext','Bytes')]
structs['RecoverSelectedResult']=[('target_id','Bytes'),('recovered','SelectionResultItemArray')]
candidate=[('candidate_id','u64'),('snapshot','Bytes'),('has_base','u32'),('base_hash','Bytes'),('new_hash','Bytes')]
structs['CandidateResult']=candidate
structs['RecoveryCandidateResult']=candidate+[('recovery_key','Bytes')]
base=[('context','Context'),('route_id','Bytes')]
adapters={
'Password':base+[('for_protection','u32')],
'Recovery':[('expected','ExpectedSnapshot')],
'Prf':base+[('credential_id','Bytes'),('prf_input','Bytes')],
'AndroidPrepare':base+[('protection','u32')],
'AndroidEncrypt':base+[(f,'Bytes') for f in ['key_ref','salt','nonce','aad','dek']],
'AndroidDecrypt':base+[(f,'Bytes') for f in ['key_ref','salt','nonce','aad','ciphertext_and_tag']],
'IosPrepare':base,
'IosEncrypt':base+[(f,'Bytes') for f in ['key_ref','salt','nonce','info','aad','dek']],
'IosDecrypt':base+[(f,'Bytes') for f in ['key_ref','ephemeral_public_key','salt','nonce','info','aad','ciphertext_and_tag']],
}
structs.update({k+'AdapterRequest':v for k,v in adapters.items()})
responses={
'Password':[('password','Bytes')], 'Recovery':[('recovery_key','Bytes')], 'Prf':[('prf_output','Bytes')],
'AndroidPrepare':[('key_ref','Bytes'),('actual_protection','u32'),('nonce','Bytes')],
'AndroidEncrypt':[('ciphertext_and_tag','Bytes')], 'AndroidDecrypt':[('dek','Bytes')],
'IosPrepare':[('key_ref','Bytes'),('ephemeral_public_key','Bytes')],
'IosEncrypt':[('ciphertext_and_tag','Bytes')], 'IosDecrypt':[('dek','Bytes')],
}
structs.update({k+'AdapterResponse':v for k,v in responses.items()})
unions={
'VaultRequestPayload':[(k.lower(),k+'Request') for k in requests],
'VaultCompletedPayload':[(k.lower(),('UnlockResult' if k=='Unlock' else 'DecryptResult' if k=='Decrypt' else 'RecoverSelectedResult' if k=='RecoverSelected' else 'RecoveryCandidateResult' if k in ['Create','ReissueRecovery'] else 'CandidateResult')) for k in requests],
'VaultAdapterRequestPayload':[(k.lower(),k+'AdapterRequest') for k in adapters],
'VaultAdapterResponsePayload':[(k.lower(),k+'AdapterResponse') for k in responses],
}
structs['VaultRequest']=[('tag','u32'),('payload','VaultRequestPayload')]
structs['VaultCompleted']=[('request_tag','u32'),('payload','VaultCompletedPayload')]
structs['VaultAdapterRequest']=[('kind','u32'),('operation_id','u64'),('request_id','u64'),('payload','VaultAdapterRequestPayload')]
structs['VaultAdapterResponse']=[('kind','u32'),('status','u32'),('payload','VaultAdapterResponsePayload')]
structs['VaultAdapterRequestArray']=array('VaultAdapterRequest')
structs['VaultPending']=[('operation_id','u64'),('requests','VaultAdapterRequestArray')]
unions['VaultStepPayload']=[('completed','VaultCompleted'),('pending','VaultPending')]
structs['VaultStep']=[('tag','u32'),('payload','VaultStepPayload')]
ct={'u8':'uint8_t','u32':'uint32_t','u64':'uint64_t'}
def ctype(t):
 if t.startswith('*const '):return 'const '+ctype(t[7:])+' *'
 return ct.get(t,t)
rust=['// Generated by tools/generate_abi.py; edit the generator.','#![allow(clippy::upper_case_acronyms)]']
header=['/* Generated by tools/generate_abi.py. */','#ifndef RUST_VAULT_H','#define RUST_VAULT_H','#include <stdint.h>','#ifdef __cplusplus','extern "C" {','#endif']
emitted=set()
def emit(name):
 if name in emitted or name in ct:return
 fields=structs.get(name,unions.get(name))
 for _,t in fields:emit(t.removeprefix('*const '))
 kind='struct' if name in structs else 'union'
 rust.extend(['#[repr(C)]','#[derive(Clone, Copy)]',f'pub {kind} {name} {{']+[f'    pub {n}: {t},' for n,t in fields]+['}'])
 header.extend([f'typedef {kind} {name} {{']+[f'    {ctype(t)} {n};' for n,t in fields]+[f'}} {name};'])
 emitted.add(name)
for name in structs:emit(name)
header+=['uint32_t vault_create(const VaultOptions *options, uint64_t *out_vault);','uint32_t vault_destroy(uint64_t vault);','uint32_t vault_begin(uint64_t vault, const VaultRequest *request, VaultStep **out_step);','uint32_t vault_resume(uint64_t vault, uint64_t operation_id, uint64_t request_id, const VaultAdapterResponse *response, VaultStep **out_step);','uint32_t vault_cancel(uint64_t vault, uint64_t operation_id);','uint32_t vault_release_context(uint64_t vault, uint64_t context_handle);','uint32_t vault_discard_candidate(uint64_t vault, uint64_t candidate_id);','uint32_t vault_confirm_saved(uint64_t vault, uint64_t candidate_id, const uint8_t *new_hash, uint32_t new_hash_len);','void vault_free_step(VaultStep *step);','#ifdef __cplusplus','}','#endif','#endif']
(root/'src/abi.rs').write_text('\n'.join(rust)+'\n')
(root/'include/rust_vault.h').write_text('\n'.join(header)+'\n')

import subprocess
subprocess.run(["rustfmt", "--edition", "2024", str(root/"src/abi.rs")], check=True)
