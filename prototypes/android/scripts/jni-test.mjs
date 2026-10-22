import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
const output=mkdtempSync(`${tmpdir()}/vault-jni-`);
function run(command,args){const r=spawnSync(command,args,{stdio:'inherit'});if(r.status!==0)throw new Error(`${command} failed`);}
try {
 run('cargo',['build','--manifest-path','rust/Cargo.toml','--locked']);
 run('javac',['-d',output,'scripts/jni-smoke/NativeRust.java']);
 run('java',[`-Djava.library.path=${resolve('rust/target/debug')}`,'-cp',output,'dev.vault.prototype.NativeRust']);
} finally {rmSync(output,{recursive:true,force:true});}
