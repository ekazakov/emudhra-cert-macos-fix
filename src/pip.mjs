/**
 * Назначение: подготовить и безопасно записать пользовательскую настройку CA для pip,
 * сохранив остальные опции и не подменяя существующий корпоративный bundle молча.
 * Основные операции:
 * 1. Получить пути конфигурации установленного pip и разобрать INI через Python.
 * 2. Проверить cert в связанных файлах и переопределения в окружении.
 * 3. Добавить global.cert, сохранив комментарии и остальные значения; dry-run не пишет.
 * 4. Создать бэкап, проверить снимки файлов, атомарно установить и проверить результат.
 * Отдельная функция подтверждает настройку через pip; Xcode и сертификаты не меняются.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {SYSTEM_BUNDLE, sha256} from './certificates.mjs';
import {timestamp} from './system.mjs';

export const APPLE_PYTHON = '/usr/bin/python3';

// Python нужен для путей установленного pip и его INI-формата. -I исключает
// импорт из cwd/PYTHONPATH; -B не позволяет создавать .pyc во время dry-run.
function python(code, {input, env = process.env} = {}) {
  const result = spawnSync(APPLE_PYTHON, ['-I', '-B', '-c', code], {
    input, encoding:'utf8', timeout:15000, maxBuffer:1024*1024, env,
  });
  if (result.error || result.status !== 0) throw new Error(`Python/pip: ${result.error?.message || result.stderr.trim() || `exit=${result.status}`}`);
  return result.stdout.trim();
}

export function pipUserConfigPaths(env = process.env) {
  // Правила macOS/XDG различаются между версиями pip. При изменении внутреннего
  // API отказываем до записи, а не угадываем путь и не создаём неактивный файл.
  const files = JSON.parse(python('import json; from pip._internal.configuration import get_configuration_files; print(json.dumps(get_configuration_files()))', {env}));
  if (!Array.isArray(files.user) || !files.user.length
    || !Object.values(files).every(list => Array.isArray(list) && list.every(file => typeof file === 'string' && path.isAbsolute(file)))) {
    throw new Error('Не удалось определить файлы конфигурации установленного pip');
  }
  const target = files.user.at(-1);
  return {target, otherFiles:[...new Set(Object.values(files).flat())].filter(file => file !== target)};
}

const PARSE_INI = `import sys,json,configparser
p=configparser.RawConfigParser()
p.read_string(sys.stdin.buffer.read().decode('utf-8'))
certs=[{'section':s,'value':p.get(s,'cert',raw=True)} for s in ['DEFAULT']+p.sections() if p.has_option(s,'cert')]
trusted=[s for s in ['DEFAULT']+p.sections() if p.has_option(s,'trusted-host') and p.get(s,'trusted-host',raw=True).strip()]
print(json.dumps({'certs':certs,'hasGlobalCert':p.has_section('global') and p.has_option('global','cert'),'trusted':trusted}))`;

export function inspectPipConfig(text) {
  try { return JSON.parse(python(PARSE_INI,{input:text})); }
  catch (error) { throw new Error('Не удалось разобрать INI pip.conf; проверьте синтаксис файла', {cause:error}); }
}

function checkCertificates(info, source) {
  if (info.certs.some(cert => cert.value !== SYSTEM_BUNDLE)) {
    throw new Error(`Конфликт настройки cert в ${source}: существующий CA-bundle не заменён. Проверьте его назначение вручную`);
  }
}

export function planPipConfig(original) {
  const info = inspectPipConfig(original);
  checkCertificates(info,'pip.conf');
  if (info.hasGlobalCert) return {candidate:original,changed:false};
  // Добавление после заголовка сохраняет комментарии, секреты и многострочные
  // значения других опций. Не сериализуем весь файл через configparser.
  const newline = original.includes('\r\n') ? '\r\n' : '\n';
  const header = /^[ \t]*\[global\][^\r\n]*(?:\r?\n|$)/m.exec(original);
  let candidate;
  if (header) {
    const end = header.index + header[0].length;
    // У существующих опций может быть отступ. Новый ключ с меньшим отступом
    // превратил бы их в продолжение cert по правилам configparser.
    const first = original.slice(end).split(/\r?\n/).find(line => line.trim() && !/^[ \t]*[#;]/.test(line));
    const indent = first && !first.trimStart().startsWith('[') ? first.match(/^[ \t]*/)[0] : '';
    const entry = `${indent}cert = ${SYSTEM_BUNDLE}${newline}`;
    candidate = original.slice(0,end) + (header[0].endsWith('\n') ? '' : newline) + entry + original.slice(end);
  } else candidate = original + (original && !original.endsWith('\n') ? newline : '') + `[global]${newline}cert = ${SYSTEM_BUNDLE}${newline}`;
  const after = inspectPipConfig(candidate);
  checkCertificates(after,'кандидате pip.conf');
  if (!after.hasGlobalCert) throw new Error('Кандидат не содержит global.cert');
  return {candidate,changed:true};
}

// Показываем все конфликты за один запуск. Просмотр плана не требует снимать
// переменные окружения; запись запрещена, пока их влияние не разобрано.
export function checkPipEnvironment(env = process.env, {dryRun = false} = {}) {
  const conflicts = [];
  if (env.PIP_CONFIG_FILE) conflicts.push('PIP_CONFIG_FILE может отключать или переопределять пользовательский pip.conf');
  for (const name of ['PIP_CERT','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE']) {
    if (env[name] && env[name] !== SYSTEM_BUNDLE) conflicts.push(`${name} указывает на другой CA-bundle и может переопределить настройку`);
  }
  if (conflicts.length && !dryRun) throw new Error(`Конфликты окружения:\n${conflicts.map(message => `- ${message}`).join('\n')}\nИзменений нет. Проверьте назначение этих переменных перед применением`);
  return conflicts.map(message => `${message}; перед применением требуется устранить конфликт`);
}

// Проверяем конечный компонент через дескриптор, чтобы не следовать символьной ссылке.
async function snapshot(target, {userOwned = true} = {}) {
  let handle;
  try { handle = await fs.open(target,fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || (userOwned && stat.uid !== process.getuid()) || (stat.mode & 0o022)) {
      throw new Error(`Небезопасный файл конфигурации: ${target}; проверьте владельца, тип, ссылки и права записи`);
    }
    const data = await handle.readFile();
    const text = data.toString('utf8');
    if (!Buffer.from(text).equals(data)) throw new Error(`Файл не в UTF-8: ${target}`);
    return {stat,text};
  } finally { await handle.close(); }
}

function sameSnapshot(left, right) {
  if (!left || !right) return left === right;
  return left.stat.dev === right.stat.dev && left.stat.ino === right.stat.ino
    && left.stat.mode === right.stat.mode && left.stat.uid === right.stat.uid
    && sha256(left.text) === sha256(right.text);
}

// Dry-run не создаёт даже каталогов. Параметры путей позволяют тестировать запись
// во временном HOME, не затрагивая реальную конфигурацию и сертификаты.
export async function fixPipUserConfig({target,otherFiles = [],dryRun = false,env = process.env}) {
  const warnings = checkPipEnvironment(env,{dryRun});
  const before = await snapshot(target);
  const checked = [];
  for (const file of [...new Set(otherFiles)]) {
    const value = await snapshot(file,{userOwned:false});
    if (value) {
      const info = inspectPipConfig(value.text);
      checkCertificates(info,file);
      if (info.trusted.length) warnings.push(`trusted-host в ${file} отключает проверку для отдельных хостов`);
    }
    checked.push({file,value});
  }
  if (inspectPipConfig(before?.text ?? '').trusted.length || env.PIP_TRUSTED_HOST) {
    warnings.push('trusted-host/PIP_TRUSTED_HOST может отключать проверку сертификатов для отдельных хостов');
  }
  const plan = planPipConfig(before?.text ?? '');
  if (dryRun || !plan.changed) return {...plan,target,backup:null,warnings};
  const parent = path.dirname(target);
  await fs.mkdir(parent,{recursive:true,mode:0o700});
  const parentStat = await fs.lstat(parent);
  if (!parentStat.isDirectory() || parentStat.uid !== process.getuid() || (parentStat.mode & 0o022)) throw new Error('Небезопасный каталог пользовательского pip.conf');
  const lock = `${target}.emudhra-lock`;
  await fs.mkdir(lock,{mode:0o700});
  let dir, backup = null;
  try {
    if (!sameSnapshot(before,await snapshot(target))) throw new Error('pip.conf изменился после проверки');
    if (before) {
      backup = `${target}.emudhra-backup.${timestamp()}.${process.pid}.${randomUUID()}`;
      const saved = await fs.open(backup,'wx',0o600);
      try { await saved.writeFile(before.text); await saved.sync(); }
      finally { await saved.close(); }
      if (sha256((await snapshot(backup)).text) !== sha256(before.text)) throw new Error(`Ошибка проверки бэкапа: ${backup}`);
    }
    dir = await fs.mkdtemp(path.join(parent,'.emudhra-pip-'));
    const staged = path.join(dir,'pip.conf');
    const handle = await fs.open(staged,'wx',0o600);
    try {
      await handle.writeFile(plan.candidate);
      await handle.chmod(before ? before.stat.mode & 0o777 : 0o600);
      await handle.sync();
    } finally { await handle.close(); }
    if (sha256((await snapshot(staged)).text) !== sha256(plan.candidate)) throw new Error('Кандидат не прошёл проверку записи');
    if (!sameSnapshot(before,await snapshot(target))) throw new Error('pip.conf изменился во время подготовки записи');
    for (const {file,value} of checked) {
      if (!sameSnapshot(value,await snapshot(file,{userOwned:false}))) throw new Error(`Другая конфигурация pip изменилась: ${file}`);
    }
    if (before) await fs.rename(staged,target);
    // Для нового файла link отказывает, если другой процесс успел создать его.
    else { await fs.link(staged,target); await fs.unlink(staged); }
    const after = await snapshot(target);
    if (sha256(after.text) !== sha256(plan.candidate) || !inspectPipConfig(after.text).hasGlobalCert) {
      throw new Error(`Проверка записи не прошла; бэкап: ${backup ?? 'файла ранее не было'}`);
    }
    return {...plan,target,backup,warnings};
  } finally {
    try { if (dir) await fs.rm(dir,{recursive:true,force:true}); }
    finally { await fs.rmdir(lock); }
  }
}

export function verifyPipUserConfig(env = process.env) {
  const result = spawnSync(APPLE_PYTHON,['-I','-B','-m','pip','config','--user','get','global.cert'],{
    env,encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
  });
  if (result.error || result.status !== 0 || result.stdout.trim() !== SYSTEM_BUNDLE) {
    throw new Error('pip не подтвердил пользовательский global.cert. Проверьте python3 -m pip config debug; автоматический откат не выполнялся');
  }
}
