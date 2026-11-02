/**
 * Назначение: проверить достоверность клиентских TLS-проб и их изоляцию,
 * чтобы ошибка окружения не считалась отклонением сертификата или чистым аудитом.
 * Основные шаги:
 * 1. Проверить классификацию сертификатных, сетевых и прикладных HTTP-ошибок.
 * 2. Испытать настоящий PipSession на локальном TLS-сервере с искусственным CA.
 * 3. Проверить исключение credentials, ошибки конфигурации и варианты Git sslVerify.
 * 4. Проверить trusted-host pip и наследование CA/клиентской идентичности Bundler.
 * Сертификаты и конфигурации создаются в tmp; вместо внешнего соединения Bundler
 * используется перехват границы создания соединения с положительным контролем.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import {execFileSync} from 'node:child_process';
import {Audit} from '../check-emudhra-certs.mjs';
import {classifyCLI,runProcess,PY_CLIENT,scanPythonClients,packageProbeEnvironment,discover,scanAdditionalClients} from '../src/clients.mjs';

test('certificate rejection differs from DNS, timeout and application HTTP errors',()=>{
  for(const kind of ['git','npm','pnpm','yarn','wget']) {
    assert.equal(classifyCLI(kind,{code:1,stdout:'',stderr:'certificate verify failed'}).status,'REJECTED');
    assert.equal(classifyCLI(kind,{code:1,stdout:'',stderr:'DNS failed'}).status,'UNKNOWN');
    assert.equal(classifyCLI(kind,{code:1,stdout:'',stderr:'E404 Not Found'}).status,'ACCEPTED');
    assert.equal(classifyCLI(kind,{code:null,stdout:'',stderr:'',error:'timeout'}).status,'UNKNOWN');
  }
  assert.equal(classifyCLI('git',{code:1,stdout:'',stderr:'requested URL returned error: 407'}).status,'UNKNOWN');
  assert.equal(classifyCLI('openssl',{code:0,stdout:'CONNECTED',stderr:''}).status,'UNKNOWN');
  assert.equal(classifyCLI('openssl',{code:0,stdout:'Verify return code: 0 (ok)',stderr:''}).status,'ACCEPTED');
  assert.equal(classifyCLI('yarn',{code:0,stdout:'',stderr:'error TLS connection failed'}).status,'UNKNOWN');
  assert.equal(classifyCLI('yarn',{code:0,stdout:'',stderr:'error unable to verify the first certificate'}).status,'REJECTED');
});

test('package-manager probes exclude user credentials and send no Authorization',async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'emudhra-auth-test-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const original={PATH:process.env.PATH,HOME:'/not-the-test-home',NPM_TOKEN:'fake-secret',NODE_AUTH_TOKEN:'fake-secret',NODE_OPTIONS:'--require fake-secret',npm_config__auth:'fake-secret'};
  const env=await packageProbeEnvironment(dir,{'strict-ssl':'true'},original);
  assert.equal(env.HOME,dir);assert.equal(env.NPM_TOKEN,undefined);assert.equal(env.NODE_AUTH_TOKEN,undefined);assert.equal(env.NODE_OPTIONS,undefined);
  assert.ok(!(await fs.readFile(env.npm_config_userconfig,'utf8')).includes('fake-secret'));
  const npm=(await discover('npm'))[0];if(!npm){t.skip('npm unavailable');return;}
  let called=false;
  const server=http.createServer((req,res)=>{called=true;assert.equal(req.headers.authorization,undefined);res.writeHead(404,{'Content-Type':'application/json'});res.end('{"error":"not found"}');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();server.close();});
  await runProcess(npm,['ping',`--registry=http://127.0.0.1:${server.address().port}/`,'--fetch-retries=0','--fetch-timeout=1000','--logs-max=0'],{env,cwd:dir});
  assert.equal(called,true);
});

test('package inventory roots do not cause REVIEW but compromised intermediates still do',async()=>{
  const roots=JSON.parse(await fs.readFile(new URL('./fixtures/roots.json',import.meta.url)));
  const intermediate=JSON.parse(await fs.readFile(new URL('./fixtures/impacted-intermediates.json',import.meta.url)))[0];
  const a=new Audit();a.scanPEM('vendored certifi',roots.map(x=>x.pem).join('\n'),{inventory:true});
  assert.equal(a.exitCode,0);assert.equal(a.sources[0].inventory,true);
  a.scanPEM('inventory',intermediate.pem,{inventory:true});assert.equal(a.findings[0].type,'COMPROMISED');
});

test('process deadline terminates a hung probe',async()=>{
  const r=await runProcess(process.execPath,['-e','setInterval(()=>{},1000)'],{timeout:50});
  assert.equal(r.error,'timeout');
});

test('Git network probe isolates authentication config and projects only TLS settings',async()=>{
  const a=new Audit();let connected=false;
  await scanAdditionalClients(a,['example.test'],true,{
    find:async name=>name==='git'?['/usr/bin/git']:[],
    run:async(file,args,options={})=>{
      if(args.includes('--version'))return {code:0,stdout:'git version fixture',stderr:''};
      if(args.includes('--get-urlmatch'))return {code:args.includes('http.sslVerify')?0:1,stdout:args.includes('http.sslVerify')?'true':'',stderr:''};
      if(args.includes('ls-remote')){
        connected=true;assert.equal(options.env.GIT_CONFIG_GLOBAL,'/dev/null');assert.equal(options.env.GIT_CONFIG_NOSYSTEM,'1');
        assert.ok(args.includes('http.sslVerify=true'));assert.ok(!options.env.NODE_OPTIONS);
        return {code:128,stdout:'',stderr:'SSL certificate problem: certificate verify failed'};
      }
      return {code:1,stdout:'',stderr:''};
    },
  });
  assert.equal(connected,true);assert.equal(a.live[0].status,'REJECTED');
});

test('missing Python client is skipped and broken API is UNKNOWN',async()=>{
  const a=new Audit();
  await scanPythonClients(a,'python',['example.test'],true,{run:async()=>({code:0,stdout:'{"absent":true}'})});
  assert.equal(a.unknown.length,0);assert.equal(a.clients.length,2);
  const b=new Audit();await scanPythonClients(b,'python',['example.test'],true,{run:async()=>({code:0,stdout:'{"status":"UNKNOWN","detail":"API mismatch"}'})});
  assert.equal(b.unknown.length,2);
});

test('real PipSession selects requested CA and rejects untrusted local certificate', {skip:process.platform!=='darwin'},async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'emudhra-client-test-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const cert=path.join(dir,'ca.pem'),key=path.join(dir,'key.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'ignore'});
  const server=https.createServer({key:await fs.readFile(key),cert:await fs.readFile(cert)},(req,res)=>{res.writeHead(404);res.end();});
  server.on('tlsClientError',()=>{});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`https://localhost:${server.address().port}/`;
  const env={PATH:'/usr/bin:/bin',HOME:dir,PIP_CONFIG_FILE:'/dev/null',NO_PROXY:'localhost'};
  const accepted=await runProcess('/usr/bin/python3',['-B','-c',PY_CLIENT,'pip',url,'live'],{env:{...env,PIP_CERT:cert}});
  const data=JSON.parse(accepted.stdout);assert.equal(data.bundle,cert);assert.equal(data.status,'ACCEPTED',accepted.stdout);
  const rejected=await runProcess('/usr/bin/python3',['-B','-c',PY_CLIENT,'pip',url,'live'],{env});
  assert.equal(JSON.parse(rejected.stdout).status,'REJECTED',rejected.stdout);
});

test('failed TLS config reads cannot produce a clean isolated probe',async()=>{
  for(const kind of ['npm','pnpm','yarn','git']){
    const a=new Audit();let network=false;
    await scanAdditionalClients(a,['example.test'],true,{
      find:async name=>name===kind?[`/fixture/${kind}`]:[],
      run:async(file,args)=>{
        if(args.includes('--version'))return {code:0,stdout:'1.0',stderr:''};
        if(args.includes('config'))return {code:1,stdout:'',stderr:'configuration error'};
        if(args.includes('ping')||args.includes('view')||args.includes('info')||args.includes('ls-remote'))network=true;
        return {code:1,stdout:'',stderr:''};
      },
    });
    assert.equal(network,false);assert.equal(a.exitCode,2);assert.ok(a.unknown.length);
  }
});

test('offline Ruby metadata failures and failed processes remain UNKNOWN',async()=>{
  for(const response of [{code:0,stdout:'{"status":"UNKNOWN","detail":"ConfigurationError"}',stderr:''},{code:1,stdout:'{"version":"fixture"}',stderr:''}]){
    const a=new Audit();
    await scanAdditionalClients(a,['example.test'],false,{
      find:async name=>name==='ruby'?['/fixture/ruby']:[],
      run:async(file,args)=>args.includes('--version')?{code:0,stdout:'ruby fixture',stderr:''}:file.endsWith('/ruby')?response:{code:1,stdout:'',stderr:''},
    });
    assert.equal(a.exitCode,2);assert.equal(a.unknown.length,3);
  }
});

test('Git normalizes off/no/false/0 and preserves absent keys',async()=>{
  for(const value of ['off','no','false','0']){
    const a=new Audit();let queried=false;
    await scanAdditionalClients(a,['example.test'],false,{
      find:async name=>name==='git'?['/usr/bin/git']:[],
      run:async(file,args,options)=>{
        if(args.includes('--version'))return {code:0,stdout:'git fixture',stderr:''};
        if(args.includes('--get-urlmatch')){
          if(args.includes('http.sslVerify')){
            assert.ok(args.includes('--bool'));queried=true;
            return runProcess('/usr/bin/git',['-c',`http.sslVerify=${value}`,...args],options);
          }
          return {code:1,stdout:'',stderr:''};
        }
        return {code:1,stdout:'',stderr:''};
      },
    });
    assert.ok(queried);assert.equal(a.findings.length,1);assert.equal(a.unknown.length,0);
  }
});

test('pip trusted-host is visible without performing network requests',{skip:process.platform!=='darwin'},async t=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'emudhra-trusted-test-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const env={PATH:'/usr/bin:/bin',HOME:dir,PIP_CONFIG_FILE:'/dev/null',PIP_TRUSTED_HOST:'example.test'};
  const a=new Audit();
  await scanPythonClients(a,'/usr/bin/python3',['example.test'],false,{run:(file,args)=>runProcess(file,args,{env})});
  assert.equal(a.clients.find(x=>x.label.endsWith(': pip')).verify,false);
  assert.ok(a.findings.some(x=>x.detail==='TLS certificate verification disabled'));
  const normal=await runProcess('/usr/bin/python3',['-B','-c',PY_CLIENT,'pip','https://example.test/','offline'],{env:{...env,PIP_TRUSTED_HOST:''}});
  assert.notEqual(JSON.parse(normal.stdout).verify,false);
  const other=new Audit();
  await scanPythonClients(other,'/usr/bin/python3',['example.test'],false,{run:(file,args)=>runProcess(file,args,{env:{...env,PIP_TRUSTED_HOST:'different.test'}})});
  assert.ok(other.findings.some(x=>x.detail==='TLS certificate verification disabled'));
});

test('Bundler blocks both certificate sources before connection and keeps CA fallback',{skip:process.platform!=='darwin'},async t=>{
  const {RUBY_PROBE}=await import('../src/clients.mjs');
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'emudhra-ruby-test-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const setup=`require 'rubygems';require 'bundler';require 'bundler/fetcher';
Gem.configuration.ssl_ca_cert='/fixture/gem-ca.pem'
class << Bundler::Fetcher; def new(*); exit! 77; end; end
`;
  for(const [gemCert,bundleCert] of [[true,false],[false,true],[true,true],[false,false]]){
    const gemrc=path.join(dir,'gemrc');
    await fs.writeFile(gemrc,gemCert?':ssl_client_cert: /fixture/gem-client.pem\n':'--- {}\n');
    const env={PATH:'/usr/bin:/bin',HOME:dir,GEMRC:gemrc,BUNDLE_SSL_CLIENT_CERT:bundleCert?'/fixture/bundle-client.pem':''};
    // Пустая строка в Ruby truthy, поэтому отсутствующее значение именно удаляем.
    if(!bundleCert)delete env.BUNDLE_SSL_CLIENT_CERT;
    const code=setup+RUBY_PROBE;
    const r=await runProcess('/usr/bin/ruby',['-e',code,'bundle','https://example.test/','live'],{env});
    if(gemCert||bundleCert){assert.equal(r.code,0,r.stderr);const info=JSON.parse(r.stdout);assert.equal(info.status,'UNKNOWN');assert.match(info.detail,/client certificate/);assert.equal(info.bundle,'/fixture/gem-ca.pem');}
    else assert.equal(r.code,77,r.stdout+r.stderr);
  }
  const r=await runProcess('/usr/bin/ruby',['-e',setup+RUBY_PROBE,'bundle','https://example.test/','offline'],{env:{PATH:'/usr/bin:/bin',HOME:dir,BUNDLE_SSL_CA_CERT:'/fixture/bundle-ca.pem'}});
  assert.equal(JSON.parse(r.stdout).bundle,'/fixture/bundle-ca.pem');
});
