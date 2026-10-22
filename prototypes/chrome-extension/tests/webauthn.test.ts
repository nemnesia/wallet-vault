import {describe,expect,it,vi} from 'vitest';
import {authentication} from '../src/webauthn';
import {prfInput} from '../src/bytes';
import {classify} from '../src/errors';
describe('WebAuthn contract',()=>{
  it('distinguishes purposes and uses exact public input bytes',()=>{
    const a=prfInput('01'.repeat(16),1),b=prfInput('01'.repeat(16),2);
    expect(new TextDecoder().decode(a.slice(0,-17))).toBe('vault-prototype/prf/v1/');
    expect(a.slice(-17,-1)).toEqual(new Uint8Array(16).fill(1));
    expect(a.at(-1)).toBe(1);expect(b.at(-1)).toBe(2);
  });
  it('fails explicitly without WebAuthn rather than providing a fake PRF',async()=>{
    vi.stubGlobal('PublicKeyCredential',undefined);
    await expect(authentication.get('01'.repeat(16),1,new Uint8Array([1]),new AbortController().signal,()=>{})).rejects.toMatchObject({code:'UNSUPPORTED'});
    vi.unstubAllGlobals();
  });
  it('does not invent the cause of NotAllowedError or expose raw exceptions',()=>{
    expect(classify(new DOMException('','NotAllowedError'))).toBe('AUTH_NOT_COMPLETED');
    expect(classify(new Error('private error data'))).toBe('INTERNAL_ERROR');
  });
});
