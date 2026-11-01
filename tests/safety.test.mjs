// Регрессии проверяем в приватных временных каталогах, без системных изменений.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { $ } from 'zx';
import {parseCertificates, summarize, removeRoots, ROOT_HEADERS, TARGET_ROOTS, COMPROMISED, sha256, readBundle, validateRestore} from '../src/certificates.mjs';
import {makeBackup, replaceWithBackup, parseArgs} from '../src/system.mjs';
import {Audit, auditFile, auditDirectory, nodeTls, scanNode, scanPython} from '../check-emudhra-certs.mjs';
import {notificationKey, deliverNotification} from '../run-emudhra-monitor.mjs';
import {stopService} from '../install-emudhra-monitor.mjs';

// Публичные сертификаты из первоисточника, загружены 01.11.2026; секретных ключей нет.
const roots = JSON.parse(await fs.readFile(new URL('./fixtures/roots.json', import.meta.url)));
const intermediates = JSON.parse(await fs.readFile(new URL('./fixtures/impacted-intermediates.json', import.meta.url)));
const section = c => `${ROOT_HEADERS.get(c.name) ?? `=== /CN=${c.name}`}\n${c.pem}\n`;
const em = roots.find(c => c.name === 'emSign ECC Root CA - G3');
const aaa = roots.find(c => c.name === 'AAA Certificate Services');
const other = roots.find(c => !TARGET_ROOTS.has(c.sha256));
const baseline = section(other);
const original = section(em) + section(aaa) + baseline;

test('published data fingerprints match DER and all local incident entries', () => {
  assert.equal(intermediates.length, 16);
  assert.deepEqual([...COMPROMISED.keys()].sort(), intermediates.map(c => c.sha256).sort());
  for (const c of [...roots, ...intermediates]) assert.equal(parseCertificates(c.pem)[0].fingerprint, c.sha256);
  for (const [hash, name] of TARGET_ROOTS) assert.ok(roots.some(c => c.sha256 === hash && c.name === name));
});

test('empty and corrupted PEM fail closed', () => {
  for (const pem of ['', '-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----', baseline + '\n-----END CERTIFICATE-----']) {
    assert.throws(() => parseCertificates(pem));
    const audit = new Audit(); audit.scanPEM('fixture', pem);
    assert.equal(audit.exitCode, 2);
  }
});

test('exact root identity, individual roots, both roots and repeat removal', () => {
  assert.deepEqual(removeRoots(baseline).removed, []);
  assert.equal(removeRoots(section(em) + baseline).text, baseline);
  assert.equal(removeRoots(section(aaa) + baseline).removed.length, 0);
  assert.equal(removeRoots(section(aaa) + baseline, {includeAAA:true}).text, baseline);
  assert.equal(removeRoots(original, {includeAAA:true}).text, baseline);
  assert.equal(removeRoots(removeRoots(original).text).removed.length, 0);
  assert.equal(summarize(original).total, 3);
});

test('compromised intermediate and Keychain roots are distinct findings', () => {
  const audit = new Audit();
  audit.scanPEM('Keychain', original, {keychain:true});
  assert.equal(audit.findings.length, 0);
  audit.scanPEM('fixture', intermediates[0].pem);
  assert.equal(audit.findings[0].type, 'COMPROMISED');
});

async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'emudhra safety & '));
  t.after(() => fs.rm(dir, {recursive:true,force:true}));
  const target = path.join(dir, 'cert.pem');
  const backup = path.join(dir, 'backup.pem');
  await fs.writeFile(target, original, {mode:0o640});
  return {dir,target,backup};
}

test('exclusive verified backup, atomic removal, then insured restoration', async t => {
  const {target,backup,dir} = await fixture(t);
  await makeBackup(target,backup);
  assert.equal(await readBundle(backup),original);
  assert.equal((await fs.stat(backup)).mode & 0o777,0o600);
  await assert.rejects(makeBackup(target,backup), {code:'EEXIST'});
  const inode = (await fs.stat(target)).ino;
  await replaceWithBackup({target,backup,candidate:baseline,expectedOriginalHash:sha256(original)});
  assert.equal(await readBundle(target),baseline);
  assert.notEqual((await fs.stat(target)).ino,inode);
  assert.equal((await fs.stat(target)).mode & 0o777,0o640);
  const insurance = path.join(dir,'insurance.pem');
  await makeBackup(target, insurance);
  const {candidate} = validateRestore(baseline,await readBundle(backup));
  await replaceWithBackup({target,backup:insurance,candidate,expectedOriginalHash:sha256(baseline)});
  assert.equal(await readBundle(target),original);
  assert.equal(await readBundle(insurance),baseline);
});

test('restore guard, force and corrupt backup validation', () => {
  assert.equal(validateRestore(baseline, original).safe,true);
  assert.throws(() => validateRestore(baseline + '# Apple update\n', original), /другие изменения/);
  assert.equal(validateRestore(baseline + '# Apple update\n', original,{force:true}).safe,false);
  assert.throws(() => validateRestore(baseline, 'broken', {force:true}));
});

test('changed source, damaged candidate or mismatched backup cannot overwrite target', async t => {
  const {target,backup} = await fixture(t);
  await makeBackup(target,backup);
  for (const options of [
    {candidate:'broken',expectedOriginalHash:sha256(original)},
    {candidate:baseline,expectedOriginalHash:sha256(baseline)},
  ]) await assert.rejects(replaceWithBackup({target,backup,...options}));
  await fs.writeFile(backup,baseline);
  await assert.rejects(replaceWithBackup({target,backup,candidate:baseline,expectedOriginalHash:sha256(original)}));
  assert.equal(await readBundle(target),original);
});

test('symlinks and hardlinks cannot become write targets', async t => {
  const {target,backup,dir} = await fixture(t);
  await makeBackup(target,backup);
  const link = path.join(dir,'link.pem');
  await fs.symlink(target,link);
  await assert.rejects(readBundle(link));
  await assert.rejects(replaceWithBackup({target:link,backup,candidate:baseline,expectedOriginalHash:sha256(original)}));
  await fs.link(target,path.join(dir,'hard.pem'));
  await assert.rejects(replaceWithBackup({target,backup,candidate:baseline,expectedOriginalHash:sha256(original)}));
  assert.equal(await readBundle(target),original);
});

test('missing required files and directories are UNKNOWN, optional Homebrew is skipped', async t => {
  const {dir} = await fixture(t);
  const missing = path.join(dir,'missing');
  const audit = new Audit();
  await auditFile(audit,new Set(),'required',missing);
  await auditDirectory(audit,new Set(),'required directory',missing);
  await auditFile(audit,new Set(),'optional',missing,{optional:true});
  assert.equal(audit.unknown.length,2);
  assert.equal(audit.exitCode,2);
});

test('access denial is UNKNOWN', {skip: process.getuid?.() === 0}, async t => {
  const {target} = await fixture(t);
  await fs.chmod(target,0);
  t.after(() => fs.chmod(target,0o600).catch(() => {}));
  const audit = new Audit();
  await auditFile(audit,new Set(),'denied',target);
  assert.equal(audit.exitCode,2);
});

test('real zx preserves spaces, quotes, dollars and argument arrays', async () => {
  const args = ['space & quote\' " $HOME `id`', 'second'];
  const result = await $({quiet:true})`${process.execPath} -e ${'console.log(JSON.stringify(process.argv.slice(1)))'} ${args}`;
  assert.deepEqual(JSON.parse(result.stdout),args);
});

test('network refusal and handshake timeout are UNKNOWN', async t => {
  const server = net.createServer(socket => { socket.on('error',()=>{}); socket.resume(); });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const port = server.address().port;
  t.after(() => server.close());
  assert.equal((await nodeTls('127.0.0.1',{port,timeout:40})).status,'UNKNOWN');
  await new Promise(resolve => server.close(resolve));
  assert.equal((await nodeTls('127.0.0.1',{port,timeout:100})).status,'UNKNOWN');
});

test('Node CA API failure is UNKNOWN', t => {
  t.mock.method(tls, 'getCACertificates', () => {throw Error('unavailable');});
  const audit = new Audit(); scanNode(audit);
  assert.equal(audit.exitCode,2);
});

test('missing or failed Python component is UNKNOWN', async () => {
  for (const binaries of [[], ['/nonexistent/emudhra-python']]) {
    const audit = new Audit();
    await scanPython(audit,new Set(),false,{binaries});
    assert.equal(audit.exitCode,2);
  }
});

test('write failure preserves original and cleans staging and lock', async t => {
  const {target,backup,dir} = await fixture(t);
  await makeBackup(target,backup);
  t.mock.method(fs,'rename',async()=>{throw Object.assign(Error('write denied'),{code:'EACCES'});});
  await assert.rejects(replaceWithBackup({target,backup,candidate:baseline,expectedOriginalHash:sha256(original)}),/write denied/);
  assert.equal(await readBundle(target),original);
  assert.deepEqual((await fs.readdir(dir)).sort(),['backup.pem','cert.pem']);
});

test('replacement detects inode race and existing writer lock', async t => {
  const {target,backup,dir} = await fixture(t);
  await makeBackup(target,backup);
  await fs.mkdir(`${target}.emudhra-lock`);
  await assert.rejects(replaceWithBackup({target,backup,candidate:baseline,expectedOriginalHash:sha256(original)}),{code:'EEXIST'});
  await fs.rmdir(`${target}.emudhra-lock`);
  const lstat = fs.lstat.bind(fs);
  let reads = 0;
  t.mock.method(fs,'lstat',async file=>{
    const stat = await lstat(file);
    if (file === target && ++reads === 2) stat.ino++;
    return stat;
  });
  await assert.rejects(replaceWithBackup({target,backup,candidate:baseline,expectedOriginalHash:sha256(original)}),/во время операции/);
  assert.equal(await readBundle(target),original);
  assert.deepEqual((await fs.readdir(dir)).sort(),['backup.pem','cert.pem']);
});

test('mixed findings and UNKNOWN changes affect notification deduplication', () => {
  const report = {exitCode:1,findings:[{type:'REVIEW',source:'bundle',detail:'AAA'}],unknown:[]};
  assert.notDeepEqual(notificationKey(report),notificationKey({...report,unknown:[{source:'Python'}]}));
});

test('failed notification is retried; saved notification is deduplicated', async () => {
  const report = {exitCode:2,findings:[],unknown:[{source:'Python'}]};
  let saved = null, attempts = 0;
  const save = async key => {saved=key;};
  await assert.rejects(deliverNotification(report,null,{send:async()=>{throw Error('denied');},save}));
  assert.equal(saved,null);
  const send = async () => {attempts++;};
  await deliverNotification(report,saved,{send,save});
  await deliverNotification(report,saved,{send,save});
  assert.equal(attempts,1);
});

test('launchctl repeat install tolerates absent service and checks other errors', async () => {
  const calls=[];
  const run=async (...args) => {calls.push(args);return {exitCode:0,stderr:''};};
  await stopService('gui/501/test',run);
  await stopService('gui/501/test',run);
  assert.deepEqual(calls.map(c=>c[0]),['print','bootout','print','bootout']);
  await stopService('test',async()=>({exitCode:113,stderr:'Could not find service "test"'}));
  await assert.rejects(stopService('test',async()=>({exitCode:1,stderr:'permission denied'})),/permission denied/);
  await assert.rejects(stopService('test',async cmd=>({exitCode:cmd==='print'?0:5,stderr:'bootout failure'})),/bootout/);
});

test('argument parser rejects inherited object properties', () => {
  assert.throws(()=>parseArgs(['toString'],{}),/Неизвестный/);
});
