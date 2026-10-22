import { fail } from './errors';
export const utf8 = new TextEncoder();
export function random(length: number): Uint8Array<ArrayBuffer> {
  try { return crypto.getRandomValues(new Uint8Array(length)); } catch { return fail('RANDOM_FAILED'); }
}
export function hex(bytes: Uint8Array): string { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
export function unhex(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[0-9a-f]{32}$/.test(value)) fail('INVALID_INPUT');
  return Uint8Array.from(value.match(/../g)!, s => Number.parseInt(s, 16));
}
export function equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v,i) => v === b[i]); }
export function base64url(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/, ''); }
export function prfInput(profileId: string, purpose: 1 | 2): Uint8Array<ArrayBuffer> {
  return new Uint8Array([...utf8.encode('vault-prototype/prf/v1/'), ...unhex(profileId), purpose]);
}
