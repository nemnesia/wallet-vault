import { hex, random } from './bytes';
import { fail } from './errors';
import type { Engine, SessionPort } from './engine';
import type { Authentication, Observe } from './webauthn';
import { validateLabel, type Snapshot, type Store } from './storage';
interface Operation { epoch: number; abort: AbortController }
export class Controller {
  private epoch = 0;
  private operation?: Operation;
  private session?: SessionPort;
  private snapshot?: Snapshot;
  private pending?: Uint8Array;
  constructor(private engine: Engine, private auth: Authentication, private storage: Store,
    private observe: Observe, private now = () => performance.now()) {}
  get state(): string { return this.operation ? 'authenticating' : this.pending ? 'prepared' : this.session ? 'unlocked' : 'locked'; }
  get requestId(): string | undefined { return this.pending ? hex(this.pending) : undefined; }
  private start(): Operation {
    if (this.operation) fail('BUSY');
    const operation = {epoch:this.epoch,abort:new AbortController()};
    this.operation = operation;
    return operation;
  }
  private current(op: Operation) {
    if (this.operation !== op || this.epoch !== op.epoch || op.abort.signal.aborted) fail('CANCELLED');
  }
  private done(op: Operation) { if (this.operation === op) this.operation = undefined; }
  async register(label: string, abortAfterIndex = false): Promise<string> {
    validateLabel(label);
    if (this.session) fail('INVALID_STATE');
    const op = this.start();
    let registration;
    try {
      registration = this.engine.registration(label);
      const profileId = hex(registration.profile_id());
      const userId = random(32);
      const credentialId = await this.auth.create(label,userId,op.abort.signal,this.observe);
      this.current(op);
      const profilePrf = await this.auth.get(profileId,1,credentialId,op.abort.signal,this.observe);
      try { this.current(op); registration.accept_profile_prf(profilePrf); } finally { profilePrf.fill(0); }
      const signingPrf = await this.auth.get(profileId,2,credentialId,op.abort.signal,this.observe);
      let bundle;
      try { this.current(op); bundle = registration.finish(signingPrf); } finally { signingPrf.fill(0); }
      let snapshot: Snapshot;
      try {
        snapshot = { formatVersion:1,revision:1,profileId,label,credentialId,userId,
          profileWrap:bundle.profile_wrap(),signingWrap:bundle.signing_wrap(),
          profileRecord:bundle.profile_record(),signingRecord:bundle.signing_record() };
      } finally { bundle.free(); }
      this.current(op);
      await this.storage.save(snapshot,op.abort.signal,abortAfterIndex);
      // A completed commit survives a concurrent lock/cancel; do not claim it was rolled back.
      this.observe('保存コミット完了。新規 Profile は locked');
      return profileId;
    } finally { registration?.free(); this.done(op); }
  }
  async open(profileId: string, options: {tamper?:boolean; alternateCredentialId?:Uint8Array} = {}): Promise<void> {
    if (this.session) fail('INVALID_STATE');
    const op = this.start();
    let session: SessionPort | undefined;
    try {
      const snapshot = await this.storage.load(profileId);
      this.current(op);
      if (options.tamper) snapshot.profileRecord[snapshot.profileRecord.length-1] ^= 1;
      session = this.engine.session(snapshot);
      const prf = await this.auth.get(profileId,1,options.alternateCredentialId ?? snapshot.credentialId,op.abort.signal,this.observe);
      try { this.current(op); session.open(prf); } finally { prf.fill(0); }
      this.session = session; session = undefined; this.snapshot = snapshot;
      this.observe('WASM で Profile 復号・tag 検証に成功。平文・鍵は WASM 内のみ');
    } finally { session?.free(); this.done(op); }
  }
  prepare(): string {
    if (this.operation) fail('BUSY');
    if (!this.session) fail('INVALID_STATE');
    this.pending = this.session.prepare(this.now());
    return hex(this.pending);
  }
  async execute(requestId?: string): Promise<boolean> {
    if (this.operation) fail('BUSY');
    if (!this.session || !this.pending || !this.snapshot || (requestId !== undefined && requestId !== hex(this.pending))) fail('INVALID_STATE');
    const pending = this.pending;
    this.pending = undefined;
    const session = this.session, snapshot = this.snapshot;
    const op = this.start();
    try {
      session.begin(pending,this.now());
      const prf = await this.auth.get(snapshot.profileId,2,snapshot.credentialId,op.abort.signal,this.observe);
      try {
        this.current(op);
        const verified = session.finish(prf,this.now());
        this.observe('WASM で Signing データ復号・照合成功（実署名ではありません）');
        return verified;
      } finally { prf.fill(0); }
    } finally {
      // Never touch a WASM instance freed by lock while WebAuthn was pending.
      if (this.session === session) session.cancel();
      this.done(op);
    }
  }
  cancel(): void {
    this.epoch++;
    this.operation?.abort.abort(); this.operation = undefined;
    this.pending = undefined; this.session?.cancel();
  }
  lock(): void {
    this.cancel();
    this.session?.lock(); this.session?.free();
    this.session = undefined; this.snapshot = undefined;
  }
}
