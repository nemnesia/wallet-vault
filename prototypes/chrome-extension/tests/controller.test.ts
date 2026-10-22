import {describe,expect,it,vi} from 'vitest';
import {Controller} from '../src/controller';
import type {Engine,SessionPort} from '../src/engine';
import type {Authentication} from '../src/webauthn';
import type {Snapshot,Store} from '../src/storage';
const snapshot:Snapshot={formatVersion:1,revision:1,profileId:'01'.repeat(16),label:'test',credentialId:new Uint8Array([1]),userId:new Uint8Array(32),profileWrap:new Uint8Array([1]),signingWrap:new Uint8Array([2]),profileRecord:new Uint8Array([3]),signingRecord:new Uint8Array([4])};
function setup() {
  const session:SessionPort={open:vi.fn(),prepare:vi.fn(()=>new Uint8Array(16)),begin:vi.fn(),finish:vi.fn(()=>true),cancel:vi.fn(),lock:vi.fn(),free:vi.fn()};
  const engine:Engine={registration:vi.fn(),session:vi.fn(()=>session)};
  const auth:Authentication={create:vi.fn(),get:vi.fn(async()=>new Uint8Array(32).fill(7))};
  const store:Store={list:vi.fn(async()=>[]),load:vi.fn(async()=>structuredClone(snapshot)),save:vi.fn()};
  return {session,engine,auth,controller:new Controller(engine,auth,store,()=>{},()=>10)};
}
describe('async lifetime boundaries (synthetic authenticator)',() => {
  it('zeroes PRF bytes, consumes before await, and refuses replay',async()=>{
    const {controller,auth,session}=setup();const bytes=new Uint8Array(32).fill(7);
    vi.mocked(auth.get).mockResolvedValue(bytes);
    await controller.open(snapshot.profileId);
    expect(bytes.every(b=>b===0)).toBe(true);
    controller.prepare();const pending=controller.execute();
    await expect(controller.execute()).rejects.toMatchObject({code:'BUSY'});
    expect(await pending).toBe(true);
    await expect(controller.execute()).rejects.toMatchObject({code:'INVALID_STATE'});
    expect(session.finish).toHaveBeenCalledTimes(1);
  });
  it('rejects a late open response after lock without touching freed WASM state',async()=>{
    const {controller,auth,session}=setup();
    let resolve!:(bytes:Uint8Array)=>void;
    const waiting=new Promise<Uint8Array>(r=>resolve=r);
    vi.mocked(auth.get).mockImplementation(()=>waiting);
    const pending=controller.open(snapshot.profileId);
    await vi.waitFor(()=>expect(auth.get).toHaveBeenCalled());
    controller.lock();const bytes=new Uint8Array(32).fill(7);resolve(bytes);
    await expect(pending).rejects.toMatchObject({code:'CANCELLED'});
    expect(session.open).not.toHaveBeenCalled();expect(session.free).toHaveBeenCalledTimes(1);
    expect(bytes.every(b=>b===0)).toBe(true);expect(controller.state).toBe('locked');
  });
  it('rejects a late probe response after lock and requires fresh authentication each time',async()=>{
    const {controller,auth,session}=setup();await controller.open(snapshot.profileId);controller.prepare();
    let resolve!:(bytes:Uint8Array)=>void;
    vi.mocked(auth.get).mockImplementation(()=>new Promise(r=>resolve=r));
    const pending=controller.execute();controller.lock();const bytes=new Uint8Array(32).fill(7);resolve(bytes);
    await expect(pending).rejects.toMatchObject({code:'CANCELLED'});
    expect(session.finish).not.toHaveBeenCalled();expect(bytes.every(b=>b===0)).toBe(true);
    expect(session.free).toHaveBeenCalledTimes(1);
  });
  it('consumes requests on failed authentication',async()=>{
    const {controller,auth,session}=setup();await controller.open(snapshot.profileId);controller.prepare();
    vi.mocked(auth.get).mockRejectedValue(new DOMException('','NotAllowedError'));
    await expect(controller.execute()).rejects.toBeInstanceOf(DOMException);
    await expect(controller.execute()).rejects.toMatchObject({code:'INVALID_STATE'});
    expect(session.finish).not.toHaveBeenCalled();
  });
});
