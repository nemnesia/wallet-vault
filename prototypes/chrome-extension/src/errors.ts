export const codes = [
  'UNSUPPORTED', 'AUTH_NOT_COMPLETED', 'CANCELLED', 'EXPIRED', 'INVALID_INPUT',
  'INTEGRITY_FAILED', 'INVALID_STATE', 'BUSY', 'STORAGE_FAILED', 'RANDOM_FAILED', 'INTERNAL_ERROR',
] as const;
export type Code = typeof codes[number];
export class Failure extends Error {
  constructor(readonly code: Code) { super(code); }
}
export function fail(code: Code): never { throw new Failure(code); }
export function classify(error: unknown): Code {
  if (error instanceof Failure) return error.code;
  // wasm-bindgen Result<T, String> throws a primitive string.
  if (typeof error === 'string' && codes.includes(error as Code)) return error as Code;
  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError') return 'AUTH_NOT_COMPLETED';
    if (error.name === 'NotSupportedError') return 'UNSUPPORTED';
    if (error.name === 'SecurityError' || error.name === 'DataError') return 'INVALID_INPUT';
  }
  return 'INTERNAL_ERROR';
}
export const messages: Record<Code, string> = {
  UNSUPPORTED: 'このブラウザ・認証器では WebAuthn PRF を利用できません。',
  AUTH_NOT_COMPLETED: '認証が完了しませんでした。拒否・取消・時間切れ・Credential 不在は区別できない場合があります。',
  CANCELLED: '操作を取り消しました。', EXPIRED: '要求の期限が切れました。',
  INVALID_INPUT: 'データ形式または認証応答・origin・設定が一致しません。',
  INTEGRITY_FAILED: '鍵またはデータの完全性が一致せず、復号を拒否しました。',
  INVALID_STATE: '操作できない状態、または無効・使用済みの要求です。', BUSY: '別の操作が進行中です。',
  STORAGE_FAILED: '保存に失敗しました。新規データはコミットされていません。',
  RANDOM_FAILED: '暗号学的乱数を取得できませんでした。', INTERNAL_ERROR: '内部処理に失敗しました。',
};
