// Read-only HTTPS-пробы через реальные клиентские библиотеки и CLI.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {X509Certificate} from 'node:crypto';

// Ограничиваем всё время процесса, включая DNS, и объём вывода. Никакого shell.
export function runProcess(file,args=[],{env=process.env,cwd,input='',timeout=12000}={}) {
  return new Promise(resolve=>{
    let stdout='',stderr='',done=false;
    const child=spawn(file,args,{env:{...env,LC_ALL:'C',PYTHONDONTWRITEBYTECODE:'1'},cwd,stdio:['pipe','pipe','pipe']});
    const finish=(code,error='')=>{if(done)return;done=true;clearTimeout(timer);resolve({code,stdout,stderr,error});};
    const timer=setTimeout(()=>{child.kill('SIGKILL');finish(null,'timeout');},timeout);
    for(const [stream,key] of [[child.stdout,'stdout'],[child.stderr,'stderr']]) stream.on('data',data=>{
      if(key==='stdout')stdout+=data;else stderr+=data;
      if(stdout.length+stderr.length>1024*1024){child.kill('SIGKILL');finish(null,'output limit');}
    });
    child.on('error',e=>finish(null,e.code||'spawn error'));
    child.on('close',code=>finish(code));
    child.stdin.on('error',()=>{});child.stdin.end(input);
  });
}

// HTTP-ошибка после завершённого TLS — принятие цепочки, а не её отклонение.
// Не классифицируем произвольный ненулевой exit как REJECTED.
export function classifyCLI(kind,result) {
  if(result.error)return {status:'UNKNOWN',detail:result.error};
  const text=result.stdout+'\n'+result.stderr;
  if(/CERT_HAS_EXPIRED|CERT_REVOKED|SELF_SIGNED_CERT|UNABLE_TO_(?:GET_ISSUER|VERIFY_LEAF)|CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSL certificate problem|server certificate verification failed|unable to get local issuer|certificate has expired|certificate verification failed|unable to verify (?:the )?first certificate|self[- ]signed certificate/i.test(text))return {status:'REJECTED',detail:'certificate verification failed'};
  if(kind==='curl')return {status:result.code===0?'ACCEPTED':[51,60].includes(result.code)?'REJECTED':'UNKNOWN',detail:`curl exit=${result.code}`};
  if(kind==='openssl') {
    if(result.code===0 && /Verify return code: 0 \(ok\)|Verification: OK/.test(text))return {status:'ACCEPTED',detail:'chain and hostname verified'};
    return {status:'UNKNOWN',detail:'OpenSSL не подтвердил проверку цепочки и имени'};
  }
  if(kind==='wget' && result.code===5)return {status:'REJECTED',detail:'wget certificate verification failure'};
  if(kind==='yarn' && /\berror\b/i.test(text) && !/404 Not Found|403 Forbidden|401 Unauthorized/i.test(text))return {status:'UNKNOWN',detail:'Yarn reported an error without a confirmed TLS outcome'};
  if(result.code===0 || /requested URL returned error: (?:400|401|403|404)|repository .* not found|\bE(?:400|401|403|404|405)\b|404 Not Found|403 Forbidden|401 Unauthorized/i.test(text))return {status:'ACCEPTED',detail:'HTTPS completed (HTTP response may be an application error)'};
  return {status:'UNKNOWN',detail:`${kind} exit=${result.code}; TLS outcome not established`};
}

// Импортируем pip в том же Python, получаем его опции install и настоящий
// PipSession. Пакеты не устанавливаем; используем GET без редиректов и записи тела.
export const PY_CLIENT = `import sys,json,importlib.util,os
kind,url=sys.argv[1:3]
module='pip' if kind=='pip' else 'requests'
if importlib.util.find_spec(module) is None:
 print(json.dumps({'absent':True}));sys.exit(0)
try:
 if kind=='pip':
  import pip
  from pip._internal.commands import create_command
  from pip._vendor import requests
  from pip._vendor import certifi
  command=create_command('install')
  options,args=command.parse_args([])
  session=command._build_session(options,retries=0,timeout=7)
  version=pip.__version__
 else:
  import requests,certifi
  session=requests.Session()
  version=requests.__version__
 # Не вызываем keyring/netrc и не передаём учётные данные тестовым хостам.
 session.auth=lambda r:r
 settings=session.merge_environment_settings(url,{},True,None,None)
 verify=settings.get('verify',session.verify)
 bundle=verify if isinstance(verify,str) else (certifi.where() if verify else None)
 info={'version':version,'bundle':bundle,'verify':verify,'bundled':certifi.where(),'truststore':type(session.get_adapter(url).poolmanager.connection_pool_kw.get('ssl_context')).__module__}
 if sys.argv[3]=='live':
  try:
   response=session.get(url,timeout=7,stream=True,allow_redirects=False)
   response.close();info.update(status='ACCEPTED',detail='TLS completed, HTTP '+str(response.status_code))
  except requests.exceptions.SSLError as e:
   # Не всякий SSL error — ошибка сертификата; EOF/handshake failure остаются UNKNOWN.
   reason=str(e).lower()
   rejected=any(t in reason for t in ('certificate_verify_failed','certificate verify failed','certificate has expired','certificate revoked','hostname mismatch','not valid for'))
   info.update(status='REJECTED' if rejected else 'UNKNOWN',detail='certificate verification failed' if rejected else 'SSL handshake failed')
  except Exception as e: info.update(status='REJECTED' if type(e).__name__=='SSLVerificationError' else 'UNKNOWN',detail=type(e).__name__)
 print(json.dumps(info))
except Exception as e: print(json.dumps({'status':'UNKNOWN','detail':'client API/config: '+type(e).__name__}))
`;

export async function scanPythonClients(audit,binary,hosts,live,{run=runProcess}={}) {
  for(const kind of ['pip','requests']) {
    const label=`${binary}: ${kind}`;
    const targets=live?hosts:[hosts[0]];
    let metadata=false;
    for(const host of targets) {
      const r=await run(binary,['-B','-c',PY_CLIENT,kind,`https://${host}/`,live?'live':'offline']);
      let data;
      try{if(r.code!==0||r.error)throw Error();data=JSON.parse(r.stdout);}catch{audit.addUnknown(label,r.error||'client probe failed');break;}
      if(data.absent){audit.clients.push({label,status:'NOT_INSTALLED'});break;}
      if(!metadata) {
        metadata=true;
        audit.clients.push({label,version:data.version,bundle:data.bundle,verify:data.verify,truststore:data.truststore});
        if(data.verify===false)audit.addFinding('REVIEW',label,'TLS certificate verification disabled');
        if(data.bundle) {
          try{audit.scanPEM(`${label}: selected CA bundle`,await fs.readFile(data.bundle,'utf8'));}
          catch{audit.addUnknown(label,'Не удалось прочитать выбранный CA bundle');}
        }
      }
      if(live)audit.addLive(label,host,data.status||'UNKNOWN',data.detail||'probe produced no TLS status');
      else if(data.status==='UNKNOWN')audit.addUnknown(label,data.detail);
    }
  }
}

// Дедуплицируем symlink, но сохраняем отдельные версии из системных, Homebrew и PATH.
export async function discover(name,extra=[]) {
  const candidates=[...extra,...['/usr/bin','/opt/homebrew/bin','/usr/local/bin',...(process.env.PATH||'').split(path.delimiter)].filter(Boolean).map(dir=>path.join(dir,name))];
  const found=new Map();
  for(const file of candidates)try{await fs.access(file,fs.constants.X_OK);const real=await fs.realpath(file);if(!found.has(real))found.set(real,file);}catch{}
  return [...found.values()];
}

// Пакетным менеджерам не передаём настоящий HOME, npmrc, токены и NODE_OPTIONS.
// Проверяется тот же executable с проекцией cafile/strict-ssl; это не полная
// проверка пользовательской конфигурации. Такой scope явно попадает в отчёт.
export async function packageProbeEnvironment(temp,settings,original=process.env) {
  const env={PATH:original.PATH||'/usr/bin:/bin',HOME:temp,XDG_CONFIG_HOME:temp,
    COREPACK_ENABLE_NETWORK:'0',npm_config_userconfig:path.join(temp,'probe.npmrc'),
    npm_config_globalconfig:'/dev/null',npm_config_cache:temp,npm_config_fetch_retries:'0',npm_config_logs_max:'0'};
  for(const key of ['NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','SSL_CERT_DIR'])if(original[key])env[key]=original[key];
  const lines=[],yarn=[];
  for(const key of ['cafile','strict-ssl']) {
    const value=settings?.[key];
    if(!value||['null','undefined'].includes(value))continue;
    if(/[\r\n]/.test(value))throw Error('TLS config contains multiple lines; isolated probe refused');
    lines.push(`${key}=${JSON.stringify(value)}`);yarn.push(`${key} ${JSON.stringify(value)}`);
  }
  await fs.writeFile(env.npm_config_userconfig,lines.join('\n')+'\n',{mode:0o600});
  await fs.writeFile(path.join(temp,'probe.yarnrc'),yarn.join('\n')+'\n',{mode:0o600});
  return env;
}

const RUBY_PROBE=`require 'json'; require 'uri'; require 'net/http'; require 'openssl'
kind,url,mode=ARGV; u=URI(url)
begin
 if kind=='gem'; require 'rubygems/remote_fetcher'; end
 if kind=='bundle'; require 'bundler'; require 'bundler/fetcher'; require 'bundler/source/rubygems/remote'; end
 info={version:RUBY_VERSION, bundle:ENV['SSL_CERT_FILE']||OpenSSL::X509::DEFAULT_CERT_FILE}
 if kind=='gem'; info[:bundle]=Gem.configuration.ssl_ca_cert||info[:bundle]; end
 if kind=='bundle'; info[:bundle]=Bundler.settings[:ssl_ca_cert]||info[:bundle]; end
 if mode=='live'
  begin
   # Не отправляем клиентский сертификат из конфигурации неизвестному test host.
   if kind=='gem' && Gem.configuration.respond_to?(:ssl_client_cert) && Gem.configuration.ssl_client_cert; raise 'client certificate configured'; end
   if kind=='bundle' && Bundler.settings[:ssl_client_cert]; raise 'client certificate configured'; end
   if kind=='gem'
    Gem::RemoteFetcher.fetcher.fetch_path(u)
   elsif kind=='bundle'
    remote=Bundler::Source::Rubygems::Remote.new(u)
    fetcher=Bundler::Fetcher.new(remote)
    connection=fetcher.send(:connection)
    connection.open_timeout=7;connection.read_timeout=7
    connection.request(u,Net::HTTP::Head.new('/'))
   else
    h=Net::HTTP.new(u.host,u.port);h.use_ssl=true;h.open_timeout=7;h.read_timeout=7;h.start{|s|s.request(Net::HTTP::Head.new('/'))}
   end
   info[:status]='ACCEPTED';info[:detail]='HTTPS completed'
  rescue => e
   text=e.message.downcase
   info[:status]=text.include?('certificate verify failed') ? 'REJECTED' : 'UNKNOWN'
   info[:detail]=e.class.name
   if kind=='gem' && text.match?(/bad response.*(?:404|403|401)/); info[:status]='ACCEPTED';end
  end
 end
 puts JSON.generate(info)
rescue LoadError
 puts JSON.generate({absent:true})
rescue => e
 puts JSON.generate({status:'UNKNOWN',detail:e.class.name})
end`;

// Perl-проба использует реальные настройки каждого установленного HTTP-модуля.
const PERL_PROBE=`use strict; use warnings; use JSON::PP; my ($kind,$url,$mode)=@ARGV;
my $module=$kind eq 'lwp'?'LWP::UserAgent':'HTTP::Tiny';
eval "require $module"; if($@){print encode_json({absent=>JSON::PP::true});exit;}
my $info={version=>eval{$module->VERSION}||'unknown',bundle=>$ENV{PERL_LWP_SSL_CA_FILE}||$ENV{SSL_CERT_FILE}};
if($kind ne 'lwp'){my $u=HTTP::Tiny->new; $info->{verify}=$u->verify_SSL?JSON::PP::true:JSON::PP::false;}
if($mode eq 'live'){
 eval{my $r; if($kind eq 'lwp'){my $ua=LWP::UserAgent->new(timeout=>7,max_redirect=>0);$ua->env_proxy;$r=$ua->get($url);my $code=$r->code;my $t=$r->as_string;$info->{status}=($code==407)?'UNKNOWN':($code==500)?(($t=~/certificate verify failed|certificate verification failed|unable to verify (?:the )?first certificate|self[- ]signed certificate/i)?'REJECTED':'UNKNOWN'):'ACCEPTED';}
 else{my $ua=HTTP::Tiny->new(timeout=>7,max_redirect=>0);$r=$ua->get($url);$info->{status}=($r->{status}==407)?'UNKNOWN':($r->{status}==599)?(($r->{content}=~/certificate verify failed|certificate verification failed|unable to verify (?:the )?first certificate|self[- ]signed certificate/i)?'REJECTED':'UNKNOWN'):'ACCEPTED';}
 $info->{detail}='HTTP transport result';};if($@){$info->{status}='UNKNOWN';$info->{detail}='Perl probe failed';}
}
print encode_json($info);`;

export async function scanAdditionalClients(audit,hosts,live,{run=runProcess,find=discover}={}) {
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'emudhra-clients-'));
  try {
    for(const kind of ['git','openssl','curl','wget','ruby','perl','npm','pnpm','yarn','npx']) {
      const extras=kind==='openssl'?['/opt/homebrew/opt/openssl@3/bin/openssl','/usr/local/opt/openssl@3/bin/openssl']:kind==='curl'?['/opt/homebrew/opt/curl/bin/curl','/usr/local/opt/curl/bin/curl']:[];
      const binaries=await find(kind,extras);
      if(!binaries.length){audit.clients.push({label:kind,status:'NOT_INSTALLED'});continue;}
      for(const binary of binaries) {
        if(kind==='curl'&&binary==='/usr/bin/curl')continue;
        const label=binary;
        // Corepack может скачивать runtime/пакетный менеджер даже на --version.
        if(/corepack/i.test(await fs.realpath(binary).catch(()=>binary))){audit.clients.push({label,status:'UNKNOWN',detail:'Corepack shim skipped: downloads prohibited'});audit.addUnknown(label,'Corepack shim не запускался');continue;}
        const v=await run(binary,[kind==='openssl'?'version':kind==='perl'?'-v':'--version'],{cwd:temp});
        const metadata={label,version:(v.stdout||v.stderr).trim().split('\n')[0].slice(0,140)};
        audit.clients.push(metadata);
        if(v.code!==0||v.error){audit.addUnknown(label,'Не удалось определить версию');continue;}
        // Читаем только CA-путь и переключатель проверки, не полный config:
        // в нём могут находиться registry tokens и пароли прокси.
        if(['git','npm','pnpm','yarn'].includes(kind)) {
          metadata.settings={};
          for(const key of kind==='git'?['http.sslCAInfo','http.sslCAPath','http.sslBackend','http.sslVerify']:['cafile','strict-ssl']) {
            const args=kind==='git'?['config','--get-urlmatch',key,`https://${hosts[0]}/`]:['config','get',key];
            const config=await run(binary,args,{cwd:temp});
            if(config.code===0)metadata.settings[key]=config.stdout.trim().slice(0,500);
          }
          if(['false','0'].includes(metadata.settings['http.sslVerify'])||metadata.settings['strict-ssl']==='false'||(kind==='git'&&process.env.GIT_SSL_NO_VERIFY))audit.addFinding('REVIEW',label,'TLS certificate verification disabled');
          const bundle=metadata.settings['http.sslCAInfo']||metadata.settings.cafile;
          if(bundle && !['null','undefined'].includes(bundle)){
            try{audit.scanPEM(`${label}: configured CA bundle`,await fs.readFile(bundle,'utf8'));}
            catch{audit.addUnknown(label,'Configured CA bundle unreadable');}
          }
        }
        if(kind==='npx'){audit.clients.push({label,detail:'npm exec wrapper; packages are never executed'});continue;}
        if(kind==='ruby'||kind==='perl') {
          for(const adapter of kind==='ruby'?['ruby','gem','bundle']:['lwp','http-tiny']) {
            for(const host of live?hosts:[hosts[0]]) {
              const script=kind==='ruby'?RUBY_PROBE:PERL_PROBE;
              const r=await run(binary,['-e',script,adapter,`https://${host}/`,live?'live':'offline'],{cwd:temp});
              let data;try{data=JSON.parse(r.stdout);}catch{audit.addUnknown(`${label} ${adapter}`,'probe failed');break;}
              if(data.absent){audit.clients.push({label:`${label} ${adapter}`,status:'NOT_INSTALLED'});break;}
              if(host===hosts[0]){audit.clients.push({label:`${label} ${adapter}`,bundle:data.bundle,version:data.version,verify:data.verify});if(data.verify===false)audit.addFinding('REVIEW',`${label} ${adapter}`,'TLS certificate verification disabled');}
              if(live)audit.addLive(`${label} ${adapter}`,host,data.status||'UNKNOWN',data.detail);
            }
          }
          continue;
        }
        if(!live)continue;
        if(kind==='yarn' && parseInt(v.stdout)>=2){audit.addUnknown(label,'Live adapter поддерживает Yarn Classic; modern Yarn не подменяется другим клиентом');continue;}
        let probeEnv={...process.env,GIT_TERMINAL_PROMPT:'0',GIT_ASKPASS:'',COREPACK_ENABLE_NETWORK:'0'};
        const gitTLS=[];
        if(kind==='git'){
          metadata.scope='isolated TLS settings; credentials/headers/project config excluded';
          probeEnv={PATH:process.env.PATH||'/usr/bin:/bin',HOME:temp,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_TERMINAL_PROMPT:'0',GIT_ASKPASS:''};
          for(const [key,value] of Object.entries(metadata.settings))gitTLS.push('-c',`${key}=${value}`);
          for(const key of ['GIT_SSL_CAINFO','GIT_SSL_CAPATH','GIT_SSL_NO_VERIFY'])if(process.env[key])probeEnv[key]=process.env[key];
        }
        if(['npm','pnpm','yarn'].includes(kind)){
          metadata.scope='isolated TLS settings only; user credentials/config excluded';
          try{probeEnv=await packageProbeEnvironment(temp,metadata.settings);}catch{audit.addUnknown(label,'Unable to isolate package manager TLS configuration');continue;}
        }
        for(const host of hosts) {
          const url=`https://${host}/`;
          if(kind==='git' && host!==hosts[0]){
            gitTLS.length=0;
            for(const key of ['http.sslCAInfo','http.sslCAPath','http.sslBackend','http.sslVerify']){
              const config=await run(binary,['config','--get-urlmatch',key,url],{cwd:temp});
              if(config.code===0)gitTLS.push('-c',`${key}=${config.stdout.trim()}`);
            }
          }
          const specs={
            git:[...gitTLS,'-c','credential.helper=','-c','core.askPass=','-c','http.followRedirects=false','ls-remote',url],
            openssl:['s_client','-connect',`${host}:443`,'-servername',host,'-verify_hostname',host,'-verify_return_error'],
            curl:['-q','-sS','-o','/dev/null','--connect-timeout','7','--max-time','10',url],
            wget:['--spider','--no-hsts','--tries=1','--timeout=7','--max-redirect=0',url],
            npm:['ping',`--registry=${url}`,'--fetch-retries=0','--fetch-timeout=7000',`--cache=${temp}`,'--logs-max=0','--ignore-scripts','--_auth=',`--//${host}/:_authToken=`],
            pnpm:['view','emudhra-audit-probe',`--registry=${url}`,],
            yarn:['--no-default-rc','--use-yarnrc',path.join(temp,'probe.yarnrc'),'info','emudhra-audit-probe',`--registry=${url}`,'--network-timeout','7000','--non-interactive',`--cache-folder=${temp}`],
          };
          const r=await run(binary,specs[kind],{cwd:temp,env:probeEnv});
          let result=classifyCLI(kind,r);
          // LibreSSL macOS не всегда поддерживает -verify_hostname: цепочку
          // проверяет клиент, имя проверяем через X509Certificate.checkHost.
          if(kind==='openssl' && /unknown|unrecognized|unsupported/i.test(r.stderr) && /verify_hostname/.test(r.stderr)){
            const fallback=await run(binary,specs[kind].filter((value,i,all)=>value!=='-verify_hostname' && all[i-1]!=='-verify_hostname'),{cwd:temp});
            result=classifyCLI(kind,fallback);
            if(result.status==='ACCEPTED'){try{const pem=fallback.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0];if(!new X509Certificate(pem).checkHost(host))result={status:'REJECTED',detail:'hostname mismatch'};}catch{result={status:'UNKNOWN',detail:'peer certificate unavailable for hostname verification'};}}
          }
          audit.addLive(label,host,result.status,result.detail);
        }
      }
    }
    await scanJava(audit,hosts,live,temp,run);
  } finally {await fs.rm(temp,{recursive:true,force:true});}
}

// /usr/bin/java на macOS — launcher, а не встроенная JVM. java_home не устанавливает JDK.
async function scanJava(audit,hosts,live,temp,run) {
  const homes=new Set();
  if(process.env.JAVA_HOME)homes.add(process.env.JAVA_HOME);
  for(const dir of ['/Library/Java/JavaVirtualMachines',path.join(os.homedir(),'Library/Java/JavaVirtualMachines'),'/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home']) {
    try{if(dir.endsWith('/Home')){await fs.access(dir);homes.add(dir);}else for(const entry of await fs.readdir(dir))homes.add(path.join(dir,entry,'Contents/Home'));}catch{}
  }
  for(const file of await discover('java')){if(file==='/usr/bin/java')continue;try{homes.add(path.dirname(path.dirname(await fs.realpath(file))));}catch{}}
  if(process.platform==='darwin'){const selected=await run('/usr/libexec/java_home',[]);if(selected.code===0&&path.isAbsolute(selected.stdout.trim()))homes.add(selected.stdout.trim());}
  if(!homes.size){audit.clients.push({label:'Java',status:'NOT_INSTALLED',detail:'macOS launcher is not a JRE'});return;}
  const source=`import javax.net.ssl.*;import java.net.*;public class AuditTLS{public static void main(String[] a){if(a.length==0){System.out.println(System.getProperty("java.version")+" | trustStore="+System.getProperty("javax.net.ssl.trustStore","default JSSE cacerts/jssecacerts"));return;}try{HttpsURLConnection c=(HttpsURLConnection)new URL(a[0]).openConnection();c.setConnectTimeout(7000);c.setReadTimeout(7000);c.setInstanceFollowRedirects(false);c.connect();System.out.println("ACCEPTED");c.disconnect();}catch(SSLHandshakeException e){String m=e.toString();System.out.println(m.contains("PKIX")||m.contains("No subject alternative")||m.contains("No name matching")?"REJECTED":"UNKNOWN");}catch(Exception e){System.out.println("UNKNOWN");}}}`;
  for(const home of homes) {
    const java=path.join(home,'bin/java'),javac=path.join(home,'bin/javac');
    await fs.writeFile(path.join(temp,'AuditTLS.java'),source);
    const compiled=await run(javac,['-d',temp,path.join(temp,'AuditTLS.java')]);
    if(compiled.code!==0||compiled.error){audit.addUnknown(java,'Java compiler unavailable; TLS probe not run');continue;}
    const meta=await run(java,['-cp',temp,'AuditTLS']);
    audit.clients.push({label:java,version:meta.stdout.trim().slice(0,200)});
    if(live)for(const host of hosts){const r=await run(java,['-cp',temp,'AuditTLS',`https://${host}/`]);const status=r.stdout.trim();audit.addLive(java,host,['ACCEPTED','REJECTED'].includes(status)?status:'UNKNOWN','JSSE HttpsURLConnection');}
  }
}
