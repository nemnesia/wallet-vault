import 'fake-indexeddb/auto';
import {beforeEach,describe,expect,it} from 'vitest';
import {store, type Snapshot} from '../src/storage';
const snapshot = (): Snapshot => ({formatVersion:1,revision:1,profileId:'01'.repeat(16),label:'test',credentialId:new Uint8Array([1]),userId:new Uint8Array(32),profileWrap:new Uint8Array([1]),signingWrap:new Uint8Array([2]),profileRecord:new Uint8Array([3]),signingRecord:new Uint8Array([4])});
beforeEach(() => { globalThis.indexedDB = new IDBFactory(); });
// fake-indexeddb's exported factory avoids sharing database state across tests.
import {IDBFactory} from 'fake-indexeddb';
describe('atomic storage',() => {
  it('persists both records and refuses duplicate registration without replacing the old one',async () => {
    const first=snapshot(); await store.save(first,new AbortController().signal);
    expect((await store.list()).length).toBe(1);
    expect((await store.load(first.profileId)).label).toBe('test');
    await expect(store.save({...first,label:'replacement'},new AbortController().signal)).rejects.toMatchObject({code:'STORAGE_FAILED'});
    expect((await store.load(first.profileId)).label).toBe('test');
  });
  it('aborts between index and body without leaving a partial profile',async () => {
    const first=snapshot();
    await expect(store.save(first,new AbortController().signal,true)).rejects.toMatchObject({code:'STORAGE_FAILED'});
    expect(await store.list()).toEqual([]);
    await expect(store.load(first.profileId)).rejects.toMatchObject({code:'INVALID_INPUT'});
  });
  it('does not save after cancellation',async () => {
    const abort=new AbortController();abort.abort();
    await expect(store.save(snapshot(),abort.signal)).rejects.toMatchObject({code:'CANCELLED'});
    expect(await store.list()).toEqual([]);
  });
});
