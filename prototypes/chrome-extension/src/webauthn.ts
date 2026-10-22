import { base64url, equal, prfInput, random } from './bytes';
import { fail, Failure } from './errors';
type PrfOutputs = { enabled?: boolean; results?: { first?: BufferSource } };
export type Observe = (stage: string) => void;
export interface Authentication {
  create(label: string, userId: Uint8Array, signal: AbortSignal, observe: Observe): Promise<Uint8Array>;
  get(profileId: string, purpose: 1|2, credentialId: Uint8Array, signal: AbortSignal, observe: Observe): Promise<Uint8Array>;
}
const buffer = (bytes: Uint8Array): ArrayBuffer => Uint8Array.from(bytes).buffer;
function supported() {
  if (!globalThis.PublicKeyCredential || !navigator.credentials) fail('UNSUPPORTED');
}
export function validateResponse(response: AuthenticatorResponse, challenge: Uint8Array, type: string): void {
  let client: {type?:string; challenge?:string; origin?:string; crossOrigin?:boolean};
  try { client = JSON.parse(new TextDecoder().decode(response.clientDataJSON)); } catch { return fail('INVALID_INPUT'); }
  if (client.type !== type || client.challenge !== base64url(challenge) || client.origin !== location.origin || client.crossOrigin === true) fail('INVALID_INPUT');
  const bytes = response instanceof AuthenticatorAttestationResponse
    ? new Uint8Array(response.getAuthenticatorData())
    : new Uint8Array((response as AuthenticatorAssertionResponse).authenticatorData);
  if (bytes.length < 37 || (bytes[32] & 5) !== 5) fail('INVALID_INPUT');
}
async function ceremony<T>(parent: AbortSignal, action: (signal: AbortSignal) => Promise<T>): Promise<T> {
  if (parent.aborted) fail('CANCELLED');
  const controller = new AbortController();
  const started = performance.now();
  let expired = false;
  const abort = () => controller.abort();
  parent.addEventListener('abort',abort,{once:true});
  const timer = setTimeout(() => { expired = true; controller.abort(); },60000);
  try {
    const result = await action(controller.signal);
    if (parent.aborted) fail('CANCELLED');
    if (expired || performance.now() - started >= 60000) fail('EXPIRED');
    return result;
  } catch (error) {
    if (parent.aborted) throw new Failure('CANCELLED');
    if (expired || performance.now() - started >= 60000) throw new Failure('EXPIRED');
    throw error;
  } finally { clearTimeout(timer); parent.removeEventListener('abort',abort); }
}
export const authentication: Authentication = {
  async create(label,userId,signal,observe) {
    supported(); const challenge = random(32);
    observe('Passkey 登録: 認証待ち');
    const result = await ceremony(signal,s => navigator.credentials.create({signal:s,publicKey:{
      rp:{name:'Vault Prototype'}, user:{id:buffer(userId),name:label,displayName:label},
      challenge:buffer(challenge), pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
      attestation:'none', authenticatorSelection:{residentKey:'preferred',userVerification:'required'},
      timeout:60000, extensions:{prf:{}} as AuthenticationExtensionsClientInputs,
    }}));
    if (!(result instanceof PublicKeyCredential) || !(result.response instanceof AuthenticatorAttestationResponse)) fail('INVALID_INPUT');
    validateResponse(result.response,challenge,'webauthn.create');
    const prf = (result.getClientExtensionResults() as {prf?:PrfOutputs}).prf;
    if (prf?.enabled !== true) fail('UNSUPPORTED');
    const credentialId = new Uint8Array(result.rawId);
    if (credentialId.length < 1 || credentialId.length > 1024) fail('INVALID_INPUT');
    observe('Passkey 登録: UV 確認、PRF enabled。出力取得は未確認');
    return credentialId;
  },
  async get(profileId,purpose,credentialId,signal,observe) {
    supported(); const challenge = random(32);
    observe(`${purpose === 1 ? 'Profile' : 'Signing'} PRF: 新規認証待ち`);
    let result: Credential | null;
    try {
      result = await ceremony(signal,s => navigator.credentials.get({signal:s,publicKey:{
        challenge:buffer(challenge), allowCredentials:[{type:'public-key',id:buffer(credentialId)}],
        userVerification:'required',timeout:60000,
        extensions:{prf:{eval:{first:buffer(prfInput(profileId,purpose))}}} as AuthenticationExtensionsClientInputs,
      }}));
    } catch(error) { throw error; }
    if (!(result instanceof PublicKeyCredential) || !(result.response instanceof AuthenticatorAssertionResponse)) fail('INVALID_INPUT');
    validateResponse(result.response,challenge,'webauthn.get');
    if (!equal(new Uint8Array(result.rawId),credentialId)) fail('INVALID_INPUT');
    const prf = (result.getClientExtensionResults() as {prf?:PrfOutputs}).prf?.results?.first;
    if (!prf) fail('UNSUPPORTED');
    const bytes = ArrayBuffer.isView(prf)
      ? new Uint8Array(prf.buffer,prf.byteOffset,prf.byteLength)
      : new Uint8Array(prf);
    if (bytes.length !== 32) { bytes.fill(0); fail('INVALID_INPUT'); }
    observe(`${purpose === 1 ? 'Profile' : 'Signing'} PRF: UV 確認、32 バイト出力あり`);
    return bytes;
  },
};
