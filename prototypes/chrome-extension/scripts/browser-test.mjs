import {chromium} from 'playwright';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {resolve} from 'node:path';
import {tmpdir} from 'node:os';
const dir=resolve('dist');
const profile=await mkdtemp(`${tmpdir()}/vault-browser-test-`);
let context;
try {
 context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${dir}`,`--load-extension=${dir}`]});
 let [worker]=context.serviceWorkers();worker??=await context.waitForEvent('serviceworker');
 const extensionId=new URL(worker.url()).host;
 // Synthetic PRF exists only in this test process, never in the packaged extension.
 await context.addInitScript(()=>{
   const syntheticAuthenticator=true;
   window.syntheticAuthenticator=syntheticAuthenticator;
   const response=(type,challenge)=>{
     const flags=new Uint8Array(37);flags[32]=5;
     const client=new TextEncoder().encode(JSON.stringify({type,challenge:btoa(String.fromCharCode(...new Uint8Array(challenge))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,''),origin:location.origin,crossOrigin:false})).buffer;
     const proto=type==='webauthn.create'?AuthenticatorAttestationResponse.prototype:AuthenticatorAssertionResponse.prototype;
     const value=Object.create(proto);
     Object.defineProperties(value,{clientDataJSON:{value:client},authenticatorData:{value:flags.buffer},getAuthenticatorData:{value:()=>flags.buffer}});
     return value;
   };
   const credential=(id,res,prf)=>{
     const value=Object.create(PublicKeyCredential.prototype);
     Object.defineProperties(value,{rawId:{value:id},response:{value:res},getClientExtensionResults:{value:()=>({prf})}});
     return value;
   };
   window.syntheticMode='normal';
   Object.defineProperty(navigator.credentials,'create',{value:async({publicKey:p})=>credential(crypto.getRandomValues(new Uint8Array(32)).buffer,response('webauthn.create',p.challenge),{enabled:true})});
   Object.defineProperty(navigator.credentials,'get',{value:async({publicKey:p,signal})=>{
     window.syntheticCalls=(window.syntheticCalls??0)+1;
     if(window.syntheticMode==='cancel') throw new DOMException('','NotAllowedError');
     const input=p.extensions.prf.eval.first;
     const id=p.allowCredentials[0].id;
     const value=await crypto.subtle.digest('SHA-256',new Uint8Array([...new Uint8Array(id),...new Uint8Array(input)]));
     const result=credential(id,response('webauthn.get',p.challenge),window.syntheticMode==='unsupported'?{}:{results:{first:value}});
     if(window.syntheticMode==='late') await new Promise(r=>setTimeout(r,250)); // deliberately ignore abort
     return result;
   }});
 });
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(`chrome-extension://${extensionId}/prototype.html`);
 await page.waitForFunction(()=>document.getElementById('state')?.textContent==='locked');
 const click=async id=>{await page.locator(`#${id}`).click();};
 const state=async expected=>page.waitForFunction(s=>document.getElementById('state')?.textContent===s,expected);
 await click('register');
 await page.waitForFunction(()=>document.querySelectorAll('#profiles option').length===1);
 await state('locked');await page.reload();await state('locked');
 assert.equal(await page.locator('#profiles option').count(),1);
 await click('open');await state('unlocked');
 await click('prepare');await state('prepared');await click('execute');await state('unlocked');
 assert.match(await page.locator('#events').innerText(),/Signing データ復号・照合成功/);
 assert.equal(await page.evaluate(()=>window.syntheticCalls),2);
 await click('prepare');await click('execute');await state('unlocked');
 assert.equal(await page.evaluate(()=>window.syntheticCalls),3);
 await click('lock');await click('tamper');
 await page.waitForFunction(()=>document.getElementById('result')?.textContent?.startsWith('INTEGRITY_FAILED'));
 await state('locked');
 await page.evaluate(()=>window.syntheticMode='cancel');await click('open');
 await page.waitForFunction(()=>document.getElementById('result')?.textContent?.startsWith('AUTH_NOT_COMPLETED'));
 await state('locked');
 await page.evaluate(()=>window.syntheticMode='late');await click('open');await click('lock');
 await page.waitForTimeout(400);await state('locked');
 await page.evaluate(()=>window.syntheticMode='unsupported');await click('open');
 await page.waitForFunction(()=>document.getElementById('result')?.textContent?.startsWith('UNSUPPORTED'));
 await page.evaluate(()=>window.syntheticMode='normal');
 await page.locator('#label').fill('second');await click('register');
 await page.waitForFunction(()=>document.querySelectorAll('#profiles option').length===2);
 await state('locked');await click('wrong-key');
 await page.waitForFunction(()=>document.getElementById('result')?.textContent?.startsWith('INTEGRITY_FAILED'));
 await state('locked');
 await page.locator('#abort-save').check();await click('register');
 await page.waitForFunction(()=>document.getElementById('result')?.textContent?.startsWith('STORAGE_FAILED'));
 await click('refresh');assert.equal(await page.locator('#profiles option').count(),2);
 assert.deepEqual(errors,[]);
 await page.screenshot({path:'/tmp/vault-chrome-prototype.png',fullPage:true});
 console.log('PASS: Chromium MV3 + actual WASM + IndexedDB roundtrip/reload, purpose separation, tamper/wrong-key rejection, cancellation/late callback, unsupported PRF, atomic abort');
 console.log('Synthetic WebAuthn only; real passkey PRF/UV/UI: NOT RUN');
} finally {await context?.close();await rm(profile,{recursive:true,force:true});}
