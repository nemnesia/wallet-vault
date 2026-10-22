import {spawnSync} from 'node:child_process';
import {platform} from 'node:os';
const windows=platform()==='win32';
const result=spawnSync(windows?'gradlew.bat':'./gradlew',[...process.argv.slice(2),'--no-daemon','--console=plain'],{cwd:'android',stdio:'inherit',shell:windows});
process.exit(result.status??1);
