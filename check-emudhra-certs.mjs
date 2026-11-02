#!/usr/bin/env node
// Проверяем CA-хранилища macOS без изменения файлов и настроек доверия.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { $ } from 'zx';
import { SYSTEM_BUNDLE, parseCertificates, readBundle, summarize, COMPROMISED } from './src/certificates.mjs';
import { parseArgs, requireMac } from './src/system.mjs';
import { keyword, colorText, rootCount } from './src/console.mjs';
import { scanPythonClients, scanAdditionalClients } from './src/clients.mjs';

// Эти тестовые хосты опубликованы на странице инцидента eMudhra.
const HOSTS = [
  'dv-g3b-emudhra.we-have-a-problem.com',
  'dv-g3b-aaa-emudhra.we-have-a-problem.com',
  'dv-g3b-noct-emudhra.we-have-a-problem.com',
  'dv-g3b-aaa-noct-emudhra.we-have-a-problem.com',
];

// Ошибки проверки сертификата отличаем от таймаута, отказа прокси и DNS.
const CERT_ERRORS = new Set([
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED', 'CERT_REVOKED',
  'CERT_UNTRUSTED', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_SIGNATURE_FAILURE',
]);

// Helper: zx выполняет только команды, для которых необходимы компоненты ОС.
async function command(commandPromise) {
  try { return await commandPromise; }
  catch (error) { return {exitCode: error.exitCode ?? 127, stdout: '', stderr: String(error.message)}; }
}

// Упаковываем события в JSON, чтобы монитор мог сравнивать находки без grep.
export class Audit {
  constructor() { this.sources = []; this.findings = []; this.unknown = []; this.live = []; this.clients = []; }
  addFinding(type, source, detail) { this.findings.push({type, source, detail}); }
  addUnknown(source, reason) { this.unknown.push({source, reason: String(reason).slice(0, 250)}); }
  scanPEM(label, pem, {keychain = false, inventory = false} = {}) {
    try {
      const result = summarize(pem);
      this.sources.push({label, certificates: result.total, em: result.em, aaa: result.aaa, keychain, inventory});
      // В Keychain присутствие корня не трактуем как доверие: macOS блокирует intermediates отдельно.
      if (!keychain && !inventory && result.em) this.addFinding('REVIEW', label, `emSign ECC Root CA - G3: ${result.em}`);
      if (!keychain && !inventory && result.aaa) this.addFinding('REVIEW', label, `AAA Certificate Services: ${result.aaa}`);
      // Промежуточный сертификат отмечаем по точному SHA-256, не по CN.
      for (const {name, sha256} of result.intermediates) this.addFinding('COMPROMISED', label, `${name} (${sha256})`);
    } catch (error) { this.addUnknown(label, error.message); }
  }
  addLive(client, host, status, detail = '') {
    this.live.push({client, host, status, detail: String(detail).slice(0, 160)});
    if (status === 'ACCEPTED') this.addFinding('ACCEPTED', client, host);
    if (status === 'UNKNOWN') this.addUnknown(client, `${host}: ${detail}`);
  }
  get exitCode() { return this.findings.length ? 1 : this.unknown.length ? 2 : 0; }
  toJSON() { return {generatedAt: new Date().toISOString(), sources: this.sources, clients: this.clients, findings: this.findings, live: this.live, unknown: this.unknown, exitCode: this.exitCode}; }
}

// Дедупликация предотвращает повторный аудит одного файла через разные переменные.
export async function auditFile(audit, seen, label, filename, {optional = false} = {}) {
  if (!filename) return;
  let actual;
  try { actual = await fs.realpath(filename); }
  catch (error) { if (!optional || error.code !== 'ENOENT') audit.addUnknown(label, error.message); return; }
  if (seen.has(actual)) return;
  seen.add(actual);
  try { audit.scanPEM(label, await readBundle(actual)); }
  catch (error) { audit.addUnknown(label, error.message); }
}

// OpenSSL CApath — каталог .pem/.crt и хешированных сертификатов; читаем через Node fs.
export async function auditDirectory(audit, seen, label, directory, {optional = false} = {}) {
  let actual, entries;
  try {
    actual = await fs.realpath(directory);
    if (seen.has(`dir:${actual}`)) return;
    seen.add(`dir:${actual}`);
    entries = await fs.readdir(actual);
  } catch (error) { if (!optional || error.code !== 'ENOENT') audit.addUnknown(label, error.message); return; }
  const files = entries.filter(name => /\.(?:pem|crt|[0-9]+)$/i.test(name)).slice(0, 500);
  if (entries.length > 500 && files.length === 500) audit.addUnknown(label, 'Превышен лимит в 500 CA-файлов');
  // Некоторые файлы в CApath — CRL, а не сертификаты; их пропускаем.
  for (const file of files) {
    const full = path.join(actual, file);
    try {
      const content = await fs.readFile(full, 'utf8');
      if (!content.includes('-----BEGIN X509 CRL-----')) await auditFile(audit, seen, `${label}/${file}`, full);
    } catch (error) { audit.addUnknown(`${label}/${file}`, error.message); }
  }
}

// security — единственная надёжная системная утилита экспорта Keychain для анализа.
async function scanKeychains(audit) {
  for (const [label, filename] of [
    ['SystemRootCertificates.keychain', '/System/Library/Keychains/SystemRootCertificates.keychain'],
    ['System.keychain', '/Library/Keychains/System.keychain'],
  ]) {
    const result = await command($({quiet: true, nothrow: true, timeout: 15000})`/usr/bin/security find-certificate -a -p ${filename}`);
    if (result.exitCode) audit.addUnknown(label, result.stderr || `exit ${result.exitCode}`);
    else if (result.stdout.includes('-----BEGIN CERTIFICATE-----')) audit.scanPEM(label, result.stdout, {keychain: true});
  }
  // Без явного пути security смотрит пользовательский список Keychain поиска.
  const user = await command($({quiet: true, nothrow: true, timeout: 15000})`/usr/bin/security find-certificate -a -p`);
  if (user.exitCode) audit.addUnknown('User Keychain', user.stderr || `exit ${user.exitCode}`);
  else if (user.stdout.includes('-----BEGIN CERTIFICATE-----')) audit.scanPEM('User Keychain', user.stdout, {keychain: true});
}

// Python используется исключительно для доступа к его реальному SSL-контексту.
const PYTHON_CONTEXT = `import ssl,sys,json,base64
ctx=ssl.create_default_context()
paths=ssl.get_default_verify_paths()
print(json.dumps({'certs':[base64.b64encode(c).decode('ascii') for c in ctx.get_ca_certs(binary_form=True)],'cafiles':[paths.cafile] if paths.cafile else [],'capaths':[paths.capath] if paths.capath else []}))`;

// certifi и vendored certifi в pip могут быть независимыми от системного trust store.
const PYTHON_CERTIFI = `import json
found=[]
for name in ('certifi','pip._vendor.certifi'):
 try:
  m=__import__(name,fromlist=['where'])
  found.append({'name':name,'file':m.where()})
 except (ImportError,AttributeError): pass
print(json.dumps(found))`;

// Проверяем прямое TLS-рукопожатие конкретного Python без стороннего pip-кода.
const PYTHON_LIVE = `import sys,ssl,socket
host=sys.argv[1]
try:
 with socket.create_connection((host,443),timeout=7) as tcp:
  with ssl.create_default_context().wrap_socket(tcp,server_hostname=host): pass
 print('ACCEPTED')
except ssl.SSLCertVerificationError as e: print('REJECTED',e.verify_message)
except (OSError,ssl.SSLError) as e: print('UNKNOWN',str(e))`;

// Находим Python 3 из PATH и типичных каталогов, избегая зависимости от bash arrays.
async function pythonExecutables() {
  const candidates = ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3'];
  for (const dir of ['/opt/homebrew/bin', '/usr/local/bin']) {
    try { candidates.push(...(await fs.readdir(dir)).filter(n => /^python3\.\d+$/.test(n)).map(n => path.join(dir, n))); }
    catch { /* Homebrew может не быть установлен. */ }
  }
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) candidates.push(path.join(dir, 'python3'));
  const found = new Map();
  for (const candidate of candidates) {
    try { const real = await fs.realpath(candidate); if (!found.has(real)) found.set(real, candidate); }
    catch { /* Отсутствующие интерпретаторы не являются ошибкой. */ }
  }
  return [...found.values()];
}

// Преобразуем DER-экспорт Python в PEM исключительно средствами Node.js.
function derToPem(base64) { return `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`; }

// Сетевой Python-проход выполняем лишь при --live-all, иначе только offline.
export async function scanPython(audit, seen, liveAll, {binaries: suppliedBinaries} = {}) {
  const binaries = suppliedBinaries ?? await pythonExecutables();
  if (!binaries.length) audit.addUnknown('Python', 'Не найден доступный интерпретатор Python 3');
  for (const binary of binaries) {
    const meta = await command($({quiet: true, nothrow: true, timeout: 12000})`${binary} -B -c ${PYTHON_CONTEXT}`);
    if (meta.exitCode) { audit.addUnknown(binary, meta.stderr || `exit ${meta.exitCode}`); continue; }
    try {
      const data = JSON.parse(meta.stdout);
      audit.scanPEM(`${binary}: default SSL context`, data.certs.map(derToPem).join(''));
      for (const filename of data.cafiles) await auditFile(audit, seen, `${binary}: cafile`, filename);
      for (const dirname of data.capaths) await auditDirectory(audit, seen, `${binary}: capath`, dirname);
    } catch (error) { audit.addUnknown(binary, error.message); }
    const certifi = await command($({quiet: true, nothrow: true, timeout: 12000})`${binary} -B -c ${PYTHON_CERTIFI}`);
    if (!certifi.exitCode) {
      // Встроенный certifi — инвентарь пакета. Фактический выбор CA проверяется
      // отдельно через PipSession/requests, а не по наличию файла на диске.
      try { for (const row of JSON.parse(certifi.stdout)) audit.scanPEM(`${binary}: ${row.name} (package inventory)`, await fs.readFile(row.file,'utf8'), {inventory:true}); }
      catch (error) { audit.addUnknown(`${binary}: certifi`, error.message); }
    } else audit.addUnknown(`${binary}: certifi`, certifi.stderr || `exit ${certifi.exitCode}`);
    await scanPythonClients(audit,binary,HOSTS,liveAll);
    if (liveAll) for (const host of HOSTS) {
      const result = await command($({quiet: true, nothrow: true, timeout: 11000})`${binary} -B -c ${PYTHON_LIVE} ${host}`);
      const [status, ...reason] = result.stdout.trim().split(/\s+/);
      audit.addLive(binary, host, ['ACCEPTED', 'REJECTED', 'UNKNOWN'].includes(status) ? status : 'UNKNOWN', reason.join(' ') || result.stderr);
    }
  }
}

// Для Node.js нужен действительный trust store именно текущего экземпляра Node.
export function scanNode(audit) {
  try {
  const sets = typeof tls.getCACertificates === 'function'
    ? ['default', 'bundled', 'system', 'extra'].map(type => [type, tls.getCACertificates(type)])
    : [['bundled (legacy API)', tls.rootCertificates]];
  for (const [name, pems] of sets) if (pems.length) audit.scanPEM(`Node.js ${name} CA`, pems.join('\n'));
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') audit.addFinding('REVIEW', 'Node.js', 'NODE_TLS_REJECT_UNAUTHORIZED=0 отключает TLS-проверку');
  } catch (error) { audit.addUnknown('Node.js CA', error.message); }
}

// Выполняем TLS-test на JS без curl, с проверкой SNI и цепочки сертификатов.
export function nodeTls(host, {port = 443, timeout = 7000} = {}) {
  return new Promise(resolve => {
    let completed = false;
    const socket = tls.connect({host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: true});
    const finish = (status, detail = '') => {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({status, detail});
    };
    // Общий таймер ограничивает также DNS lookup, который socket timeout не покрывает.
    const timer = setTimeout(() => finish('UNKNOWN', 'timeout'), timeout);
    socket.once('secureConnect', () => finish('ACCEPTED'));
    socket.once('timeout', () => finish('UNKNOWN', 'timeout'));
    socket.once('error', e => finish(CERT_ERRORS.has(e.code) ? 'REJECTED' : 'UNKNOWN', e.code ?? e.message));
  });
}

// /usr/bin/curl тестируем отдельно: это иной клиент с другим CA-store.
async function scanLive(audit, mode) {
  if (!mode) return;
  for (const host of HOSTS) {
    // -q должен идти первым: пользовательский .curlrc может содержать insecure.
    const result = await command($({quiet: true, nothrow: true, timeout: 15000})`/usr/bin/curl -q --silent --show-error --output /dev/null --connect-timeout 7 --max-time 12 ${`https://${host}/`}`);
    const status = result.exitCode === 0 ? 'ACCEPTED' : [51, 60].includes(result.exitCode) ? 'REJECTED' : 'UNKNOWN';
    audit.addLive('/usr/bin/curl', host, status, `curl exit=${result.exitCode}; ${result.stderr ?? ''}`);
  }
  if (mode === 'all') for (const host of HOSTS) {
    const result = await nodeTls(host);
    audit.addLive('Node.js TLS', host, result.status, result.detail);
  }
}

// Основной проход: сначала локальные источники, затем только по запросу сеть.
export async function runAudit({liveMode = '', macOnly = true} = {}) {
  if (macOnly) requireMac();
  const audit = new Audit();
  const seen = new Set();
  await auditFile(audit, seen, '/etc/ssl/cert.pem', SYSTEM_BUNDLE);
  if (process.platform === 'darwin') await scanKeychains(audit);
  for (const prefix of ['/opt/homebrew', '/usr/local']) {
    for (const name of ['etc/ca-certificates/cert.pem', 'etc/openssl@3/cert.pem', 'etc/openssl@1.1/cert.pem', 'etc/openssl/cert.pem']) {
      await auditFile(audit, seen, `Homebrew ${prefix}`, path.join(prefix, name), {optional: true});
    }
    for (const name of ['etc/ca-certificates/certs', 'etc/openssl@3/certs']) {
      await auditDirectory(audit, seen, `Homebrew ${prefix}`, path.join(prefix, name), {optional: true});
    }
  }
  for (const name of ['SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE', 'PIP_CERT', 'NODE_EXTRA_CA_CERTS']) {
    if (process.env[name]) await auditFile(audit, seen, name, process.env[name]);
  }
  for (const directory of (process.env.SSL_CERT_DIR || '').split(':').filter(Boolean)) {
    await auditDirectory(audit, seen, 'SSL_CERT_DIR', directory);
  }
  await scanPython(audit, seen, liveMode === 'all');
  scanNode(audit);
  await scanLive(audit, liveMode);
  await scanAdditionalClients(audit,HOSTS,liveMode === 'all');
  return audit;
}

// Текстовый вывод остаётся похожим на предыдущий Bash-скрипт.
function printHuman(audit) {
  for (const source of audit.sources) {
    console.log(`${source.keychain || source.inventory ? '[INFO]' : '[STORE]'} ${source.label}: ${source.certificates} сертификатов; ${rootCount('emSign', source.em)}, ${rootCount('AAA', source.aaa)}`);
  }
  for (const client of audit.clients) console.log(`[CLIENT] ${client.label}: ${client.status || client.version || 'detected'}${client.bundle ? `; CA=${client.bundle}` : ''}${client.scope ? `; scope=${client.scope}` : ''}${client.settings ? `; settings=${JSON.stringify(client.settings)}` : ''}${client.truststore ? `; context=${client.truststore}` : ''}${client.verify === false ? '; TLS verification disabled' : ''}${client.detail ? `; ${client.detail}` : ''}`);
  for (const finding of audit.findings) {
    const tone = finding.type === 'COMPROMISED' ? 'red' : finding.type === 'REVIEW' ? 'yellow' : undefined;
    console.log(`[${keyword(finding.type)}] ${finding.source}: ${colorText(finding.detail, tone)}`);
  }
  for (const result of audit.live) console.log(`[${keyword(result.status)}] ${result.client}: ${result.host} ${result.detail}`);
  for (const item of audit.unknown) console.log(`[${keyword('UNKNOWN')}] ${item.source}: ${item.reason}`);
  const resultTone = {0: 'green', 1: 'red', 2: 'yellow'}[audit.exitCode];
  console.log(colorText(`RESULT: exit=${audit.exitCode} (0=нет находок, 1=проверить, 2=неполная проверка)`, resultTone));
  console.log('Наличие корня в bundle не доказывает принятие опасной TLS-цепочки.');
}

// Если модуль запущен напрямую, а не импортирован тестами, обрабатываем CLI.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const opts = parseArgs(process.argv.slice(2), {'--live': true, '--live-all': true, '--json': true, '--help': true});
    if (opts['--help']) console.log('node check-emudhra-certs.mjs [--live | --live-all] [--json]');
    else {
      const audit = await runAudit({liveMode: opts['--live-all'] ? 'all' : opts['--live'] ? 'curl' : ''});
      if (opts['--json']) console.log(JSON.stringify(audit.toJSON(), null, 2));
      else printHuman(audit);
      process.exitCode = audit.exitCode;
    }
  } catch (error) {console.error(`${keyword('ERROR', process.stderr)}: ${error.message}`); process.exitCode = 2;}
}
