import React,{useCallback,useEffect,useState} from 'react';
import {Alert,AppState,Button,NativeModules,SafeAreaView,ScrollView,Share,StyleSheet,Switch,Text,TextInput,View} from 'react-native';
type Profile={id:string;label:string};
type Report={state:string;busy:boolean;requestId:string|null;profiles:Profile[];events:{time:string;stage:string}[];environment:Record<string,unknown>};
interface Adapter {
 status():Promise<string>;register(label:string,abort:boolean):Promise<string>;open(id:string,mode:string):Promise<string>;
 prepare():Promise<string>;execute(id:string):Promise<string>;cancel():Promise<string>;lock():Promise<string>;deleteSigningKey():Promise<string>;
}
const vault=NativeModules.VaultPrototype as Adapter;
const messages:Record<string,string>={UNSUPPORTED:'強い生体認証を利用できません。登録・端末対応を確認してください。',CANCELLED:'取消しました。',EXPIRED:'期限が切れました。',AUTH_NOT_COMPLETED:'認証が完了しませんでした。',KEY_INVALIDATED:'OS鍵が失効または削除されています。',INTEGRITY_FAILED:'鍵または暗号文が一致せず、復号を拒否しました。',INVALID_INPUT:'入力または保存データが不正です。',INVALID_STATE:'操作できない状態・要求です。',BUSY:'別の操作が進行中です。',STORAGE_FAILED:'保存に失敗しました。',INTERNAL_ERROR:'内部処理に失敗しました。',RANDOM_FAILED:'乱数取得に失敗しました。'};
export default function App(){
 const [report,setReport]=useState<Report>();const [selected,setSelected]=useState('');
 const [label,setLabel]=useState('検証Profile');const [abort,setAbort]=useState(false);
 const [message,setMessage]=useState('初期化中');const [provider,setProvider]=useState('');const [observation,setObservation]=useState('');
 const refresh=useCallback(async()=>{
  const value=JSON.parse(await vault.status()) as Report;setReport(value);
  setSelected(old=>value.profiles.some(p=>p.id===old)?old:value.profiles[0]?.id??'');
 },[]);
 useEffect(()=>{void refresh().catch(()=>setMessage('初期化に失敗しました。Nativeライブラリと保存状態を確認してください。'));
  const timer=setInterval(()=>{void refresh().catch(()=>{});},1000);
  const sub=AppState.addEventListener('change',state=>{if(state==='active')void refresh().catch(()=>{});});
  return()=>{clearInterval(timer);sub.remove();};},[refresh]);
 const run=async(action:()=>Promise<string>)=>{
  try{const result=JSON.parse(await action()) as Report;setReport(result);setMessage('操作成功。実際の認証画面の挙動を観測欄に記録してください。');}
  catch(error){const code=(error as {code?:string}).code??'INTERNAL_ERROR';setMessage(`${code}: ${messages[code]??messages.INTERNAL_ERROR}`);}
  finally{await refresh().catch(()=>{});}
 };
 const state=report?.state??'initializing',busy=report?.busy??true,locked=state==='locked';
 const button=(title:string,action:()=>Promise<string>,disabled=false)=><View style={styles.button}><Button title={title} color="#205d4f" disabled={disabled} onPress={()=>{void run(action);}}/></View>;
 return <SafeAreaView style={styles.safe}><ScrollView contentContainerStyle={styles.main} keyboardShouldPersistTaps="handled">
  <Text style={styles.eyebrow}>VAULT / ANDROID PROTOTYPE</Text><Text style={styles.title}>OS鍵で保護し、{ '\n' }Rustで復号する。</Text>
  <Text style={styles.help}>削除予定の検証用アプリです。実運用の秘密情報は入力しません。強い生体認証を使い、PINへ自動切替しません。</Text>
  <View style={styles.card}><Text style={styles.heading}>実行環境</Text><Text selectable>{JSON.stringify(report?.environment??{},null,2)}</Text>
   <TextInput style={styles.input} value={provider} onChangeText={setProvider} placeholder="実際の認証方式: 指紋 / 顔認証など" maxLength={120}/></View>
  <View style={styles.card}><Text style={styles.heading}>1. 登録・暗号化・保存</Text><TextInput style={styles.input} value={label} onChangeText={setLabel} maxLength={64}/>
   <View style={styles.row}><Switch value={abort} onValueChange={setAbort}/><Text>保存途中abortを注入</Text></View>
   {button('生体認証して登録・保存',()=>vault.register(label,abort),busy||!locked)}
   <Text style={styles.help}>用途ごとの保護鍵を登録するため、認証を2回行います。成功後もlockedです。</Text></View>
  <View style={styles.card}><Text style={styles.heading}>2. 保存済みProfile</Text>
   {report?.profiles.map(p=><View key={p.id} style={styles.button}><Button color={selected===p.id?'#205d4f':'#728780'} title={`${selected===p.id?'✓ ':''}${p.label} · ${p.id.slice(0,8)}`} disabled={busy} onPress={()=>{void run(async()=>{await vault.lock();setSelected(p.id);return vault.status();});}}/></View>)}
   {button('一覧を更新',()=>vault.status(),busy)}
   {button('再認証してProfileを復号',()=>vault.open(selected,'normal'),busy||!locked||!selected)}
   {button('一回限りの要求を準備',()=>vault.prepare(),busy||state!=='unlocked')}
   {button('再認証してSigningデータを照合',()=>vault.execute(report?.requestId??''),busy||state!=='prepared')}
   <Text style={styles.help}>照合は実署名ではありません。アプリを終了して開き直し、保存済みデータを再解除できるかも確認してください。</Text></View>
  <View style={styles.card}><Text style={styles.heading}>状態: {state}{busy?' / 認証処理中':''}</Text><Text>要求: {report?.requestId??'なし'}</Text>
   {button('取消',()=>vault.cancel(),!report)}{button('ロック',()=>vault.lock(),!report)}
   {button('改ざんしたコピーで復号を試す',()=>vault.open(selected,'tamper'),busy||!locked||!selected)}
   {button('別のOS鍵で復号を試す',()=>vault.open(selected,'wrong-key'),busy||!locked||!selected||(report?.profiles.length??0)<2)}
   <View style={styles.button}><Button title="検証用Signing鍵を削除（復旧不可）" color="#9b442f" disabled={busy||locked||!report} onPress={()=>Alert.alert('署名用の検証鍵を削除','このProfileのSigning用OS鍵だけを削除します。照合できなくなり、復旧できません。',[
    {text:'取消',style:'cancel'},{text:'検証鍵を削除',style:'destructive',onPress:()=>{void run(()=>vault.deleteSigningKey());}},
   ])}/></View></View>
  <View style={styles.card}><Text style={styles.heading}>観測ログ</Text><Text selectable accessibilityLiveRegion="polite">{message}</Text>
   <TextInput style={styles.input} multiline value={observation} onChangeText={setObservation} placeholder="毎回認証されたか・認証方法など。鍵や秘密値を記入しないでください" maxLength={2000}/>
   <Button title="非秘密の結果を共有" color="#205d4f" onPress={()=>{void Share.share({message:JSON.stringify({kind:'manual-observation',...report,provider,observation,note:'実機の合否は実行者の観測と合わせて判定。自動PASSではありません。'},null,2)}).catch(()=>{});}}/>
   {report?.events.map((e,i)=><Text key={i} style={styles.event} selectable>{e.time} {e.stage}</Text>)}
  </View>
 </ScrollView></SafeAreaView>;
}
const styles=StyleSheet.create({safe:{flex:1,backgroundColor:'#edf2f1'},main:{padding:22,paddingBottom:50},eyebrow:{fontSize:12,letterSpacing:2,color:'#37645b',fontWeight:'700'},title:{fontSize:32,lineHeight:44,fontWeight:'700',color:'#172b32',marginVertical:18},card:{backgroundColor:'#fff',borderRadius:12,padding:18,marginVertical:10},heading:{fontSize:18,fontWeight:'600',color:'#172b32',marginBottom:14},help:{color:'#52646a',fontSize:13,lineHeight:21,marginVertical:10},input:{borderWidth:1,borderColor:'#a6bbb5',borderRadius:6,padding:12,color:'#172b32',marginVertical:10},button:{marginVertical:6},row:{flexDirection:'row',alignItems:'center',gap:10},event:{fontSize:11,color:'#52646a',marginVertical:6}});
