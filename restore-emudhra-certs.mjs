#!/usr/bin/env node
/**
 * Назначение: восстановить системный CA-bundle из явно выбранной резервной копии,
 * сохранив возможность отменить восстановление и не откатить чужие изменения молча.
 * Основные шаги:
 * 1. Показать допустимые бэкапы либо прочитать текущий файл и указанный пользователем.
 * 2. Проверить PEM/X.509 и определить, ограничены ли отличия целевыми корнями.
 * 3. При сторонних отличиях потребовать force; при dry-run показать план без записи.
 * 4. Создать страховочную копию, выполнить проверенную замену и сообщить результат.
 * Бэкап автоматически не выбирается; force не разрешает повреждённый PEM.
 */
import fs from 'node:fs/promises';
import { SYSTEM_BUNDLE, readBundle, validateRestore, sha256 } from './src/certificates.mjs';
import { requireMac, parseArgs, makeBackup, replaceWithBackup, timestamp } from './src/system.mjs';

// Список разрешённых имён строго соответствует форматам старых и новых скриптов.
function supportedBackup(file) {
  return file === `${SYSTEM_BUNDLE}.orig`
    || /^\/etc\/ssl\/cert\.pem\.emudhra-backup\.(?:\d{8}-\d{6}|\d{8}-\d{6}Z?)\.\d+$/.test(file);
}

// Выводим все распознанные резервные копии, не выбирая одну молча.
async function listBackups() {
  const files = await fs.readdir('/etc/ssl');
  for (const name of files.sort()) {
    const file = `/etc/ssl/${name}`;
    if (supportedBackup(file) && (await fs.lstat(file)).isFile()) console.log(file);
  }
}

// Все ограничения проверяем до административной замены PEM.
async function main() {
  const opts = parseArgs(process.argv.slice(2), {'--list': true, '--backup': 'value', '--dry-run': true, '--force': true, '--help': true});
  if (opts['--help']) {
    console.log('node restore-emudhra-certs.mjs --list | --backup /etc/ssl/cert.pem.emudhra-backup.YYYYMMDD-HHMMSS.PID [--dry-run] [--force]');
    return;
  }
  requireMac();
  if (opts['--list']) {
    if (opts['--backup']) throw new Error('--list нельзя использовать вместе с --backup');
    await listBackups();
    return;
  }
  const backup = opts['--backup'];
  if (!backup || !supportedBackup(backup)) throw new Error('Укажите конкретный допустимый путь через --backup (предварительно --list)');
  const [current, previous] = await Promise.all([readBundle(SYSTEM_BUNDLE), readBundle(backup)]);
  const {safe} = validateRestore(current, previous, {force: Boolean(opts['--force'])});
  console.log(`Резервная копия: ${backup}; ${safe ? 'отличия только в двух корнях' : 'ВНИМАНИЕ: принудительный откат других изменений'}`);
  if (opts['--dry-run']) {console.log('DRY-RUN: запись не выполнялась.'); return;}
  if (process.getuid?.() !== 0) throw new Error('Для восстановления запустите sudo node restore-emudhra-certs.mjs --backup ...');
  // Страховочная копия сохраняет текущее состояние, если потребуется отменить откат.
  const preRestore = `${SYSTEM_BUNDLE}.before-restore.${timestamp()}.${process.pid}`;
  await makeBackup(SYSTEM_BUNDLE, preRestore);
  console.log(`Копия состояния до восстановления: ${preRestore}`);
  await replaceWithBackup({candidate: previous, backup: preRestore, expectedOriginalHash: sha256(current)});
  console.log('Восстановление успешно. Проверьте TLS: node check-emudhra-certs.mjs --live');
}

// Отсутствие бэкапа, повреждение или неожиданные отличия должны остановить откат.
main().catch(error => {console.error(`ERROR: ${error.message}`); process.exitCode = 2;});
