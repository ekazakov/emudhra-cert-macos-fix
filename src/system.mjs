/**
 * Назначение: сосредоточить общие ограничения CLI и безопасную замену CA-bundle,
 * чтобы команды удаления и восстановления использовали один файловый протокол.
 * Основные операции:
 * 1. Проверять macOS и допустимые аргументы командной строки.
 * 2. Создавать эксклюзивный бэкап и сверять его с исходным файлом.
 * 3. Блокировать параллельную запись наших CLI и проверять тип, inode и хеш цели.
 * 4. Записывать и синхронизировать кандидата рядом с целью, затем делать rename.
 * После замены содержимое сверяется; блокировка не защищает от сторонних редакторов.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { SYSTEM_BUNDLE, sha256, readBundle, parseCertificates } from './certificates.mjs';

// Отказываемся изменять хранилища на других ОС.
export function requireMac() {
  if (process.platform !== 'darwin') throw new Error('Этот скрипт предназначен для macOS');
}

// Обрабатываем только явно перечисленные параметры; это защищает от опечаток.
export function parseArgs(args, allowed) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (!Object.hasOwn(allowed, key)) throw new Error(`Неизвестный параметр: ${key}`);
    if (allowed[key] === 'value') {
      if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`Не указан аргумент для ${key}`);
      options[key] = args[++i];
    } else options[key] = true;
  }
  return options;
}

// Копируем оригинальный системный bundle с EXCL, чтобы не затереть старый бэкап.
export async function makeBackup(from, to) {
  const original = await readBundle(from);
  parseCertificates(original);
  await fs.writeFile(to, original, {flag: 'wx', mode: 0o600});
  if (sha256(original) !== sha256(await readBundle(to)) || sha256(original) !== sha256(await readBundle(from))) {
    throw new Error(`Бэкап не совпадает с оригиналом: ${to}`);
  }
  await fs.chmod(to, 0o600);
  return to;
}

// rename в том же каталоге не оставляет частично записанный системный bundle.
// Перед commit повторно сверяем inode и содержимое; чужие изменения не откатываем.
export async function replaceWithBackup({target = SYSTEM_BUNDLE, candidate, backup, expectedOriginalHash}) {
  // mkdir с фиксированным именем не допускает параллельные записи наших CLI.
  // После аварии блокировку удаляет оператор, убедившись, что процесса больше нет.
  const lock = `${target}.emudhra-lock`;
  await fs.mkdir(lock, {mode: 0o700});
  try { return await replaceLocked({target, candidate, backup, expectedOriginalHash}); }
  finally { await fs.rmdir(lock); }
}

async function replaceLocked({target, candidate, backup, expectedOriginalHash}) {
  parseCertificates(candidate);
  const stat = await fs.lstat(target);
  if (!stat.isFile() || stat.nlink !== 1) throw new Error('Цель должна быть обычным файлом без дополнительных жёстких ссылок');
  if (sha256(await readBundle(target)) !== expectedOriginalHash || sha256(await readBundle(backup)) !== expectedOriginalHash) {
    throw new Error('Файл изменился после проверки. Повторите операцию с новым бэкапом');
  }
  const dir = await fs.mkdtemp(path.join(path.dirname(target), '.emudhra-'));
  const staged = path.join(dir, 'candidate.pem');
  try {
    const handle = await fs.open(staged, 'wx', 0o600);
    try {
      await handle.writeFile(candidate);
      await handle.chown(stat.uid, stat.gid);
      await handle.chmod(stat.mode & 0o777);
      await handle.sync();
    } finally { await handle.close(); }
    if (sha256(await readBundle(staged)) !== sha256(candidate)) throw new Error('Ошибка проверки кандидата');
    const latest = await fs.lstat(target);
    if (latest.dev !== stat.dev || latest.ino !== stat.ino || latest.nlink !== 1 || sha256(await readBundle(target)) !== expectedOriginalHash) {
      throw new Error('Целевой файл заменён или изменён во время операции');
    }
    await fs.rename(staged, target);
    if (sha256(await readBundle(target)) !== sha256(candidate)) throw new Error(`Проверка записи не прошла; резервная копия: ${backup}`);
  } finally { await fs.rm(dir, {recursive: true, force: true}); }
}

// Дата без символов двоеточия подходит для безопасных имён файлов macOS.
export const timestamp = () => new Date().toISOString().replace(/[-:]/g, '').replace(/T/, '-').replace(/\..*/, '');
