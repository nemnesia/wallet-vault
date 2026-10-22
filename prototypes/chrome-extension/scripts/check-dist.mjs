import {readFileSync,readdirSync,statSync} from 'node:fs';
import assert from 'node:assert/strict';
const manifest=JSON.parse(readFileSync('dist/manifest.json','utf8'));
assert.equal(manifest.manifest_version,3);
assert.ok(manifest.key);
for (const key of ['host_permissions','content_scripts','externally_connectable','permissions']) assert.equal(manifest[key],undefined);
assert.ok(manifest.content_security_policy.extension_pages.includes("'wasm-unsafe-eval'"));
function files(dir){return readdirSync(dir).flatMap(name=>{const p=`${dir}/${name}`;return statSync(p).isDirectory()?files(p):[p];});}
const all=files('dist');
assert.ok(all.some(p=>p.endsWith('.wasm')));
assert.ok(all.includes('dist/background.js'));
for(const p of all.filter(p=>p.endsWith('.js'))){
 const code=readFileSync(p,'utf8');
 assert.ok(!code.includes('syntheticAuthenticator'),`test authenticator leaked into ${p}`);
}
console.log('PASS: packaged WASM, MV3 permissions and test-code isolation');
