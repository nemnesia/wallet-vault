/* Public non-production test inputs only; no secret values are printed. */
#include "rust_vault.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static Bytes b(const void *p, uint32_t n) { return (Bytes){p,n}; }
static uint32_t vector(const char *name, uint8_t *out) {
    FILE *f=fopen("tests/fixtures/v1.txt","r"); assert(f);
    char line[8192]; uint32_t size=0;
    while(fgets(line,sizeof line,f)) {
        if(strncmp(line,name,strlen(name)) || line[strlen(name)]!='=') continue;
        const char *p=line+strlen(name)+1;
        while(p[0] && p[0]!='\n') { unsigned byte=0;assert(sscanf(p,"%2x",&byte)==1);out[size++]=(uint8_t)byte;p+=2; }
        break;
    }
    fclose(f);assert(size);return size;
}
int main(void) {
    VaultOptions options = {UINT64_C(134217728)};
    uint64_t vault = 0, other = 0;
    assert(vault_create(&options, &vault) == 0 && vault != 0);
    VaultOptions different = {options.memory_budget_bytes + 1};
    assert(vault_create(&different, &other) == 1 && other == 0);
    RoutePlan route = {3,2,{NULL,0},{NULL,0},0};
    route.credential_id = b("public-test-credential",22);
    PurposeInput input = {{b("a",1),&route,1},b("public payload",14)};
    VaultRequest request = {.tag=1,.payload.create={b("t",1),{&input,1}}};
    VaultStep *step = NULL;
    assert(vault_begin(vault,&request,&step)==0 && step && step->tag==2);
    uint64_t op = step->payload.pending.operation_id;
    uint64_t rid = step->payload.pending.requests.items[0].request_id;
    uint8_t public_prf[32]; memset(public_prf,0x51,sizeof public_prf);
    VaultAdapterResponse response = {.kind=3,.status=0,.payload.prf={b(public_prf,32)}};
    VaultStep *next = (VaultStep *)(uintptr_t)1;
    assert(vault_resume(vault,op,rid+1,&response,&next)==8 && next==NULL);
    vault_free_step(step);
    assert(vault_resume(vault,op,rid,&response,&step)==0);
    /* New PRF wrap is independently unlocked before the candidate is returned. */
    assert(step->tag==2 && step->payload.pending.requests.items[0].kind==3);
    op=step->payload.pending.operation_id;rid=step->payload.pending.requests.items[0].request_id;
    vault_free_step(step);
    assert(vault_resume(vault,op,rid,&response,&step)==0 && step->tag==1);
    RecoveryCandidateResult c=step->payload.completed.payload.create;
    assert(c.has_base==0 && c.base_hash.len==0 && c.new_hash.len==32 && c.recovery_key.len==32);
    assert(c.snapshot.len>11 && !memcmp(c.snapshot.ptr,"RVLT",4));
    assert(vault_confirm_saved(vault,c.candidate_id,c.new_hash.ptr,c.new_hash.len)==0);
    uint8_t data[4096], wrap[4096], recovery[32];
    uint32_t data_len=vector("data",data), wrap_len=vector("recovery_wrap",wrap);
    assert(vector("recovery",recovery)==32);
    Context context={b("public-test-target",18),b("public-test-purpose",19),1};
    SelectionInput selected={context,b(data,data_len),b(wrap,wrap_len)};
    VaultRequest recover={.tag=11,.payload.recoverselected={{&selected,1},1}};
    VaultStep *selected_step=NULL;
    assert(vault_begin(vault,&recover,&selected_step)==0 && selected_step->tag==2);
    op=selected_step->payload.pending.operation_id;rid=selected_step->payload.pending.requests.items[0].request_id;
    VaultAdapterResponse recovery_response={.kind=2,.status=0,.payload.recovery={b(recovery,32)}};
    vault_free_step(selected_step);
    assert(vault_resume(vault,op,rid,&recovery_response,&selected_step)==0 && selected_step->tag==1);
    uint64_t handle=selected_step->payload.completed.payload.recoverselected.recovered.items[0].context_handle;
    vault_free_step(selected_step);
    for (int i=0;i<16;i++) {
        uint64_t another=0;assert(vault_create(&options,&another)==0);
        assert(another!=handle); /* Owner and key handles share one namespace. */
        assert(vault_destroy(another)==0);
    }
    VaultRequest decrypt={.tag=5,.payload.decrypt={handle,context,b(data,data_len)}};
    assert(vault_begin(vault,&decrypt,&selected_step)==0 && selected_step->tag==1);
    Bytes plaintext=selected_step->payload.completed.payload.decrypt.plaintext;
    assert(plaintext.len==26 && !memcmp(plaintext.ptr,"public test-only plaintext",26));
    vault_free_step(selected_step);
    assert(vault_begin(vault,&decrypt,&selected_step)==8 && selected_step==NULL);
    uint8_t password_wrap[4096], password[1024];
    uint32_t pw_len=vector("password",password), pw_wrap_len=vector("password_wrap",password_wrap);
    VaultRequest unlock={.tag=4,.payload.unlock={context,b(data,data_len),b(password_wrap,pw_wrap_len),1}};
    assert(vault_begin(vault,&unlock,&selected_step)==0 && selected_step->tag==2);
    op=selected_step->payload.pending.operation_id;rid=selected_step->payload.pending.requests.items[0].request_id;
    VaultAdapterResponse password_response={.kind=1,.status=0,.payload.password={b(password,pw_len)}};
    vault_free_step(selected_step);
    assert(vault_resume(vault,op,rid,&password_response,&selected_step)==0 && selected_step->tag==1);
    handle=selected_step->payload.completed.payload.unlock.context_handle;vault_free_step(selected_step);
    decrypt.payload.decrypt.context_handle=handle;
    assert(vault_begin(vault,&decrypt,&selected_step)==0);
    plaintext=selected_step->payload.completed.payload.decrypt.plaintext;
    assert(plaintext.len==26 && !memcmp(plaintext.ptr,"public test-only plaintext",26));vault_free_step(selected_step);
    /* An outstanding result keeps the original process budget after destroy. */
    assert(vault_destroy(vault)==0);
    assert(vault_create(&different,&other)==1);
    vault_free_step(step);
    assert(vault_create(&different,&other)==0);
    VaultStep *bad=(VaultStep *)(uintptr_t)1;
    assert(vault_begin(other,NULL,&bad)==1 && bad==NULL);
    assert(vault_destroy(other)==0);
    return 0;
}
