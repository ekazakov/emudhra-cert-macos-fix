/**
 * Назначение: проверить настройку пользовательского pip.conf без изменения
 * настоящей конфигурации пользователя, Xcode и системных сертификатов.
 * Основные шаги:
 * 1. Подготовить временный HOME и варианты INI с комментариями и конфликтами.
 * 2. Проверить выбор пути, dry-run, сохранение опций, бэкап и повторный запуск.
 * 3. Испытать ошибки записи, небезопасные ссылки и права, блокировки и переменные.
 * 4. Подтвердить настройку настоящим pip и проверить отказ CLI от запуска через sudo.
 * Зависящие от Python Apple сценарии выполняются только на macOS.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {APPLE_PYTHON, pipUserConfigPaths, inspectPipConfig, planPipConfig, checkPipEnvironment, fixPipUserConfig, verifyPipUserConfig} from '../src/pip.mjs';

const mac = {skip:process.platform !== 'darwin'};
async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(),'emudhra pip & '));
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const env = {PATH:'/usr/bin:/bin',HOME:dir,XDG_CONFIG_HOME:path.join(dir,'.config')};
  return {dir,env,target:path.join(dir,'pip.conf')};
}

test('pip plan preserves comments, multiline options, CRLF and indentation',mac,()=>{
  for (const original of [
    '', '# comment', '[install]\nretries = 2\n', '[global]',
    '# header\n[global]\n# comment\ntimeout = 30\nfind-links =\n    https://example.test/packages\n',
    '[global]\n    timeout = 60\n    disable-pip-version-check = true\n',
    '[global]\r\nindex-url = https://example.test/%25\r\n',
  ]) {
    const {candidate,changed} = planPipConfig(original);
    assert.equal(changed,true);
    assert.equal(inspectPipConfig(candidate).hasGlobalCert,true);
    assert.deepEqual(planPipConfig(candidate),{candidate,changed:false});
    if (original.includes('timeout')) assert.ok(candidate.includes(original.slice(original.indexOf('timeout'))));
    if (original.includes('\r\n')) assert.equal(candidate.replaceAll('\r\n','').includes('\n'),false);
  }
});

test('pip rejects conflicts, command overrides, defaults and malformed INI',mac,()=>{
  for (const text of [
    '[global]\ncert = /company.pem\n',
    '[install]\ncert = /company.pem\n',
    '[DEFAULT]\ncert = /company.pem\n[global]\ntimeout = 1\n',
    '[global]\ncert = /etc/ssl/cert.pem\n[download]\ncert = /company.pem\n',
    'broken INI', '[global]\n[global]\n',
    '[global]\ncert = /etc/ssl/cert.pem\ncert = /etc/ssl/cert.pem\n',
  ]) assert.throws(()=>planPipConfig(text));
});

test('pip refuses environment overrides without replacing them',()=>{
  for (const env of [{PIP_CONFIG_FILE:'/dev/null'},{PIP_CERT:'/company.pem'},{REQUESTS_CA_BUNDLE:'/company.pem'},{CURL_CA_BUNDLE:'/company.pem'}]) assert.throws(()=>checkPipEnvironment(env));
  assert.doesNotThrow(()=>checkPipEnvironment({PIP_CERT:'/etc/ssl/cert.pem'}));
});

test('pip lists all environment conflicts together and permits read-only planning',mac,async t=>{
  const {target,dir,env:clean} = await fixture(t);
  const env = {...clean,PIP_CERT:'/company.pem',REQUESTS_CA_BUNDLE:'/requests.pem',CURL_CA_BUNDLE:'/curl.pem',PIP_CONFIG_FILE:'/dev/null'};
  const result = await fixPipUserConfig({target,env,dryRun:true});
  assert.equal(result.changed,true);
  assert.equal(result.warnings.length,4);
  for (const name of ['PIP_CERT','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','PIP_CONFIG_FILE']) {
    assert.ok(result.warnings.some(message=>message.includes(name)));
  }
  await assert.rejects(fixPipUserConfig({target,env}),error=>{
    for (const name of ['PIP_CERT','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','PIP_CONFIG_FILE']) assert.ok(error.message.includes(name));
    return true;
  });
  assert.deepEqual(await fs.readdir(dir),[]);
});

test('pip discovers paths of installed pip and dry-run creates nothing',mac,async t=>{
  const {dir,env} = await fixture(t);
  const {target,otherFiles} = pipUserConfigPaths(env);
  assert.ok(target.startsWith(dir+path.sep));
  assert.ok(otherFiles.includes(path.join(dir,'.pip','pip.conf')));
  const result = await fixPipUserConfig({target,env,dryRun:true});
  assert.equal(result.changed,true);
  assert.deepEqual(await fs.readdir(dir),[]);
});

test('pip respects existing macOS Application Support configuration directory',mac,async t=>{
  const {dir,env} = await fixture(t);
  const preferred = path.join(dir,'Library','Application Support','pip');
  await fs.mkdir(preferred,{recursive:true});
  const {target} = pipUserConfigPaths(env);
  assert.equal(target,path.join(preferred,'pip.conf'));
});

test('real pip reads newly installed user config, repeated fix is a no-op',mac,async t=>{
  const {env} = await fixture(t);
  const {target} = pipUserConfigPaths(env);
  const result = await fixPipUserConfig({target,env});
  assert.equal(result.backup,null);
  assert.equal((await fs.stat(target)).mode & 0o777,0o600);
  verifyPipUserConfig(env);
  const inode = (await fs.stat(target)).ino;
  assert.equal((await fixPipUserConfig({target,env})).changed,false);
  assert.equal((await fs.stat(target)).ino,inode);
  assert.deepEqual(await fs.readdir(path.dirname(target)),['pip.conf']);
});

test('existing pip config is preserved and saved in private backup before replacement',mac,async t=>{
  const {target,env} = await fixture(t);
  const original = '# keep comment\n[global]\nindex-url = https://example.test/simple\ntimeout = 20\n';
  await fs.writeFile(target,original,{mode:0o640});
  const result = await fixPipUserConfig({target,env});
  assert.ok(result.backup);
  assert.equal(await fs.readFile(result.backup,'utf8'),original);
  assert.equal((await fs.stat(result.backup)).mode & 0o777,0o600);
  assert.equal((await fs.stat(target)).mode & 0o777,0o640);
  assert.equal(await fs.readFile(target,'utf8'),original.replace('[global]\n','[global]\ncert = /etc/ssl/cert.pem\n'));
});

test('legacy or site cert conflict prevents writing user config',mac,async t=>{
  const {target,dir,env} = await fixture(t);
  const other = path.join(dir,'legacy.conf');
  await fs.writeFile(other,'[global]\ncert = /company.pem\n');
  await assert.rejects(fixPipUserConfig({target,env,otherFiles:[other]}),/Конфликт/);
  assert.deepEqual(await fs.readdir(dir),['legacy.conf']);
});

test('already configured file is not rewritten or backed up',mac,async t=>{
  const {target,dir,env} = await fixture(t);
  const original = '# keep\n[global]\nCERT: /etc/ssl/cert.pem\n';
  await fs.writeFile(target,original);
  assert.equal((await fixPipUserConfig({target,env})).changed,false);
  assert.equal(await fs.readFile(target,'utf8'),original);
  assert.deepEqual(await fs.readdir(dir),['pip.conf']);
});

test('pip refuses symlinks, hardlinks, unsafe permissions and invalid UTF-8',mac,async t=>{
  const {target,dir,env} = await fixture(t);
  const other = path.join(dir,'other.conf');
  await fs.writeFile(other,'# original');
  await fs.symlink(other,target);
  await assert.rejects(fixPipUserConfig({target,env}));
  await fs.unlink(target);
  await fs.link(other,target);
  await assert.rejects(fixPipUserConfig({target,env}));
  await fs.unlink(target);
  await fs.writeFile(target,Buffer.from([0xff]));
  await assert.rejects(fixPipUserConfig({target,env}),/UTF-8/);
  await fs.writeFile(target,''); await fs.chmod(target,0o666);
  await assert.rejects(fixPipUserConfig({target,env}),/Небезопасный/);
  assert.equal(await fs.readFile(other,'utf8'),'# original');
});

test('write failure retains original and verified backup, cleans lock and staging',mac,async t=>{
  const {target,dir,env} = await fixture(t);
  await fs.writeFile(target,'# original\n');
  t.mock.method(fs,'rename',async()=>{throw Error('write failed');});
  await assert.rejects(fixPipUserConfig({target,env}),/write failed/);
  assert.equal(await fs.readFile(target,'utf8'),'# original\n');
  const files = await fs.readdir(dir);
  assert.equal(files.length,2);
  assert.ok(files.some(name=>name.startsWith('pip.conf.emudhra-backup.')));
});

test('existing writer lock is not removed',mac,async t=>{
  const {target,env} = await fixture(t);
  await fs.mkdir(`${target}.emudhra-lock`);
  await assert.rejects(fixPipUserConfig({target,env}),{code:'EEXIST'});
  assert.ok((await fs.stat(`${target}.emudhra-lock`)).isDirectory());
});

test('trusted-host is reported rather than mistaken for validated TLS',mac,async t=>{
  const {target,env} = await fixture(t);
  await fs.writeFile(target,'[global]\ntrusted-host = example.test\n');
  const result = await fixPipUserConfig({target,env,dryRun:true});
  assert.match(result.warnings[0],/trusted-host/);
});

test('post-write pip verification fails when user config is ignored',mac,async t=>{
  const {env} = await fixture(t);
  assert.throws(()=>verifyPipUserConfig({...env,PIP_CONFIG_FILE:'/dev/null'}),/не подтвердил/);
});

test('pip CLI rejects sudo before touching configuration',mac,t=>{
  const result = spawnSync(process.execPath,['--input-type=module','-e',
    'process.getuid=()=>0; process.argv[1]=process.cwd()+"/fix-pip-certs.mjs"; await import("./fix-pip-certs.mjs");'],{encoding:'utf8'});
  assert.equal(result.status,2,result.stderr);
  assert.match(result.stderr,/без sudo/);
});
