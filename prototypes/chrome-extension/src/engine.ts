import init, { Registration, VaultSession } from '../pkg/vault';
import wasmUrl from '../pkg/vault_bg.wasm?url';
import { unhex } from './bytes';
import type { Snapshot } from './storage';
export interface BundlePort {
  profile_wrap(): Uint8Array; signing_wrap(): Uint8Array;
  profile_record(): Uint8Array; signing_record(): Uint8Array; free(): void;
}
export interface RegistrationPort {
  profile_id(): Uint8Array; accept_profile_prf(bytes: Uint8Array): void;
  finish(bytes: Uint8Array): BundlePort; free(): void;
}
export interface SessionPort {
  open(bytes: Uint8Array): void; prepare(now: number): Uint8Array;
  begin(id: Uint8Array, now: number): void; finish(bytes: Uint8Array, now: number): boolean;
  cancel(): void; lock(): void; free(): void;
}
export interface Engine {
  registration(label: string): RegistrationPort;
  session(snapshot: Snapshot): SessionPort;
}
export async function loadEngine(): Promise<Engine> {
  await init({module_or_path:wasmUrl});
  return {
    registration: label => new Registration(label),
    session: s => new VaultSession(unhex(s.profileId),s.label,s.profileWrap,s.signingWrap,s.profileRecord,s.signingRecord),
  };
}
