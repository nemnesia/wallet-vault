import {spawnSync} from 'node:child_process';
import {existsSync,mkdirSync,copyFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {homedir,platform} from 'node:os';
const sdk=process.env.ANDROID_HOME??process.env.ANDROID_SDK_ROOT??join(homedir(),'Android','Sdk');
const ndk=process.env.ANDROID_NDK_HOME??join(sdk,'ndk','27.1.12297006');
const host=platform()==='win32'?'windows-x86_64':platform()==='darwin'?'darwin-x86_64':'linux-x86_64';
const bin=join(ndk,'toolchains','llvm','prebuilt',host,'bin');
const extension=platform()==='win32'?'.cmd':'';
for(const [target,abi,clang] of [['aarch64-linux-android','arm64-v8a','aarch64-linux-android30-clang'],['x86_64-linux-android','x86_64','x86_64-linux-android30-clang']]){
 const linker=join(bin,clang+extension);
 if(!existsSync(linker))throw new Error(`NDK linker not found: ${linker}. Set ANDROID_NDK_HOME.`);
 const prefix=`CARGO_TARGET_${target.toUpperCase().replaceAll('-','_')}`;
 const env={...process.env,[`${prefix}_LINKER`]:linker,[`${prefix}_RUSTFLAGS`]:'-Clink-arg=-Wl,-z,max-page-size=16384'};
 const result=spawnSync('cargo',['build','--manifest-path','rust/Cargo.toml','--locked','--release','--target',target],{stdio:'inherit',env});
 if(result.status!==0)process.exit(result.status??1);
 const destination=resolve('android','app','src','main','jniLibs',abi);mkdirSync(destination,{recursive:true});
 copyFileSync(join('rust','target',target,'release','libvault_android.so'),join(destination,'libvault_android.so'));
}
