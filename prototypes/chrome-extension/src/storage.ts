import { fail, Failure } from './errors';
import { unhex, utf8 } from './bytes';
export interface IndexEntry { profileId: string; label: string; unlockMethod: 'passkey-prf' }
export interface Snapshot {
  formatVersion: 1; profileId: string; label: string; revision: 1;
  credentialId: Uint8Array; userId: Uint8Array;
  profileWrap: Uint8Array; signingWrap: Uint8Array; profileRecord: Uint8Array; signingRecord: Uint8Array;
}
export function validateLabel(label: unknown): asserts label is string {
  if (typeof label !== 'string' || utf8.encode(label).length < 1 || utf8.encode(label).length > 64) fail('INVALID_INPUT');
}
export function validateIndex(value: unknown): asserts value is IndexEntry {
  if (!value || typeof value !== 'object') fail('INVALID_INPUT');
  const v = value as IndexEntry;
  if (typeof v.profileId !== 'string') fail('INVALID_INPUT');
  unhex(v.profileId); validateLabel(v.label);
  if (v.unlockMethod !== 'passkey-prf') fail('INVALID_INPUT');
}
export function validateSnapshot(value: unknown, index: IndexEntry): asserts value is Snapshot {
  validateIndex(index);
  if (!value || typeof value !== 'object') fail('INVALID_INPUT');
  const v = value as Snapshot;
  if (v.formatVersion !== 1 || v.revision !== 1 || v.profileId !== index.profileId || v.label !== index.label) fail('INVALID_INPUT');
  for (const key of ['credentialId','userId','profileWrap','signingWrap','profileRecord','signingRecord'] as const) {
    if (!(v[key] instanceof Uint8Array) || v[key].length === 0 || v[key].length > 4096) fail('INVALID_INPUT');
  }
  if (v.credentialId.length > 1024 || v.userId.length !== 32) fail('INVALID_INPUT');
}
function connect(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('vault-prototype-v1', 1);
    request.onupgradeneeded = () => { request.result.createObjectStore('index'); request.result.createObjectStore('profiles'); };
    request.onsuccess = () => { request.result.onversionchange = () => request.result.close(); resolve(request.result); };
    request.onerror = () => reject(new Failure('STORAGE_FAILED'));
    request.onblocked = () => reject(new Failure('STORAGE_FAILED'));
  });
}
export async function listProfiles(): Promise<IndexEntry[]> {
  const db = await connect();
  return new Promise((resolve,reject) => {
    const tx = db.transaction('index','readonly');
    const request = tx.objectStore('index').getAll();
    tx.oncomplete = () => {
      db.close();
      try { const entries: unknown[] = request.result; entries.forEach(validateIndex); resolve(entries as IndexEntry[]); }
      catch { reject(new Failure('INVALID_INPUT')); }
    };
    tx.onabort = () => { db.close(); reject(new Failure('STORAGE_FAILED')); };
  });
}
export async function loadProfile(profileId: string): Promise<Snapshot> {
  unhex(profileId);
  const db = await connect();
  return new Promise((resolve,reject) => {
    const tx = db.transaction(['index','profiles'],'readonly');
    const index = tx.objectStore('index').get(profileId);
    const body = tx.objectStore('profiles').get(profileId);
    tx.oncomplete = () => {
      db.close();
      try { validateSnapshot(body.result,index.result); resolve(body.result); }
      catch { reject(new Failure('INVALID_INPUT')); }
    };
    tx.onabort = () => { db.close(); reject(new Failure('STORAGE_FAILED')); };
  });
}
export async function saveProfile(snapshot: Snapshot, signal: AbortSignal, abortAfterIndex = false): Promise<void> {
  const index: IndexEntry = { profileId: snapshot.profileId, label: snapshot.label, unlockMethod: 'passkey-prf' };
  validateSnapshot(snapshot,index);
  const db = await connect();
  if (signal.aborted) { db.close(); fail('CANCELLED'); }
  return new Promise((resolve,reject) => {
    const tx = db.transaction(['index','profiles'],'readwrite');
    const abort = () => { try { tx.abort(); } catch { /* already committed */ } };
    const done = () => { signal.removeEventListener('abort',abort); db.close(); };
    signal.addEventListener('abort',abort,{once:true});
    tx.oncomplete = () => { done(); resolve(); };
    tx.onabort = () => { done(); reject(new Failure(signal.aborted ? 'CANCELLED' : 'STORAGE_FAILED')); };
    const first = tx.objectStore('index').add(index,snapshot.profileId);
    first.onsuccess = () => {
      if (abortAfterIndex) tx.abort();
      else tx.objectStore('profiles').add(snapshot,snapshot.profileId);
    };
  });
}
export interface Store {
  list: typeof listProfiles; load: typeof loadProfile; save: typeof saveProfile;
}
export const store: Store = {list:listProfiles,load:loadProfile,save:saveProfile};
