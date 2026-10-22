import {spawnSync} from 'node:child_process';
import {existsSync} from 'node:fs';
const apk='android/app/build/outputs/apk/release/app-release.apk';
if(!existsSync(apk))throw new Error('Run npm run build first.');
const result=spawnSync('adb',['install','-r',apk],{stdio:'inherit'});
process.exit(result.status??1);
