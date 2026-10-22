import './style.css';
import { loadEngine } from './engine';
import { authentication } from './webauthn';
import { store } from './storage';
import { Controller } from './controller';
import { classify, messages } from './errors';
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const select = $<HTMLSelectElement>('profiles');
const log: {time:string;operation:number;stage:string}[] = [];
let operation = 0;
let controller: Controller | undefined;
function observe(stage: string) {
  log.push({time:new Date().toISOString(),operation,stage});
  if (log.length > 200) log.shift();
  const li = document.createElement('li'); li.textContent = `${log.at(-1)!.time} #${operation} ${stage}`;
  $('events').append(li);
  while ($('events').children.length > 200) $('events').firstElementChild?.remove();
  li.scrollIntoView({block:'nearest'});
  render();
}
function render() {
  const state = controller?.state ?? 'initializing';
  $('state').textContent = state;
  $('request').textContent = controller?.requestId ? `準備済み要求: ${controller.requestId}（60秒で失効）` : '準備済み要求なし';
  const ready = !!controller, busy = state === 'authenticating', locked = state === 'locked', selected = !!select.value;
  for (const id of ['register','refresh','open','prepare','execute','cancel','lock','tamper','wrong-key']) {
    $<HTMLButtonElement>(id).disabled = !ready;
  }
  $<HTMLButtonElement>('register').disabled = !ready || !locked;
  $<HTMLButtonElement>('refresh').disabled = !ready || busy;
  for (const id of ['open','tamper']) $<HTMLButtonElement>(id).disabled = !locked || !selected;
  $<HTMLButtonElement>('wrong-key').disabled = !locked || !selected || select.options.length < 2;
  $<HTMLButtonElement>('prepare').disabled = state !== 'unlocked';
  $<HTMLButtonElement>('execute').disabled = state !== 'prepared';
  select.disabled = busy;
}
async function refresh(preferred = select.value) {
  const entries = await store.list();
  select.replaceChildren();
  for (const entry of entries) {
    const option = document.createElement('option'); option.value = entry.profileId;
    option.textContent = `${entry.label} · ${entry.profileId.slice(0,8)}`; select.append(option);
  }
  if (entries.some(e => e.profileId === preferred)) select.value = preferred;
  render();
}
async function run(action: () => Promise<void> | void) {
  const number = ++operation;
  const start = performance.now();
  try {
    const pending = action(); render(); await pending;
    if (number === operation) $('result').textContent = '操作成功。実認証器・認証画面の観測を記録してください。';
    observe(`操作完了 (${Math.round(performance.now()-start)} ms)`);
  } catch(error) {
    const code = classify(error);
    if (number === operation) $('result').textContent = `${code}: ${messages[code]}`;
    observe(`${code} (${Math.round(performance.now()-start)} ms)`);
  } finally { render(); }
}
$('register').onclick = () => void run(async () => {
  const id = await controller!.register($<HTMLInputElement>('label').value,$<HTMLInputElement>('abort-save').checked);
  await refresh(id);
});
$('refresh').onclick = () => void run(() => refresh());
$('open').onclick = () => void run(() => controller!.open(select.value));
$('prepare').onclick = () => void run(() => { controller!.prepare(); });
$('execute').onclick = () => void run(async () => { await controller!.execute(); });
$('cancel').onclick = () => { operation++; controller?.cancel(); $('result').textContent = '取消しました。完了済みの保存は維持されます。'; observe('取消・準備済み要求を破棄'); };
$('lock').onclick = () => { operation++; controller?.lock(); $('result').textContent = 'ロックしました。'; observe('Session を破棄して locked'); };
select.onchange = () => { controller?.lock(); observe('Profile 切替: 旧 Session を破棄'); };
$('tamper').onclick = () => void run(() => controller!.open(select.value,{tamper:true}));
$('wrong-key').onclick = () => void run(async () => {
  const alternate = [...select.options].find(o => o.value !== select.value)!;
  const snapshot = await store.load(alternate.value);
  await controller!.open(select.value,{alternateCredentialId:snapshot.credentialId});
});
$('copy').onclick = async () => {
  const evidence = {kind:'manual-observation',userAgent:navigator.userAgent,origin:location.origin,
    provider:$<HTMLInputElement>('provider').value,events:log,observation:$<HTMLTextAreaElement>('observation').value,
    note:'実認証器の合否は実行者が検証IDごとに判定。自動PASSではありません。'};
  try { await navigator.clipboard.writeText(JSON.stringify(evidence,null,2)); $('result').textContent = '結果をコピーしました。'; }
  catch { $('result').textContent = 'コピーできませんでした。ブラウザのクリップボード権限を確認してください。'; }
};
$('environment').textContent = `${navigator.userAgent}\n${location.origin}`;
try {
  const engine = await loadEngine();
  controller = new Controller(engine,authentication,store,observe);
  await refresh(); render(); $('result').textContent = '準備完了。Passkeyを登録してください。';
} catch(error) { const code=classify(error); $('result').textContent = `${code}: ${messages[code]}`; }
