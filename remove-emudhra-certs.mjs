#!/usr/bin/env node
// Удаление строго выбранных корневых сертификатов; ключ AAA опционален.
import { SYSTEM_BUNDLE, readBundle, summarize, removeRoots, sha256 } from './src/certificates.mjs';
import { requireMac, parseArgs, makeBackup, replaceWithBackup, timestamp } from './src/system.mjs';
import { keyword, colorText, rootCount } from './src/console.mjs';

// Управляем выполнением только из JS: исключаем обработку аргументов shell.
async function main() {
  const opts = parseArgs(process.argv.slice(2), {'--dry-run': true, '--include-aaa': true, '--help': true});
  if (opts['--help']) {
    console.log('node remove-emudhra-certs.mjs [--dry-run] [--include-aaa]');
    return;
  }
  requireMac();
  // Считываем исходный bundle без изменения времени или прав доступа.
  const original = await readBundle(SYSTEM_BUNDLE);
  const before = summarize(original);
  const {text, removed} = removeRoots(original, {includeAAA: Boolean(opts['--include-aaa'])});
  console.log(`Найдено: ${rootCount('emSign', before.em)}, ${rootCount('AAA', before.aaa)}; планируется удалить: ${removed.map(name => colorText(name, 'yellow')).join(', ') || 'ничего'}`);
  if (!removed.length || opts['--dry-run']) {
    console.log(opts['--dry-run'] ? `${keyword('DRY-RUN')}: изменения не выполнены.` : 'Удалять нечего.');
    return;
  }
  if (process.getuid?.() !== 0) throw new Error('Для изменения /etc/ssl/cert.pem запустите sudo node remove-emudhra-certs.mjs');
  // Создаём уникальный бэкап перед каждой операцией. Не удаляем его автоматически.
  const backup = `${SYSTEM_BUNDLE}.emudhra-backup.${timestamp()}.${process.pid}`;
  await makeBackup(SYSTEM_BUNDLE, backup);
  console.log(`Резервная копия: ${backup}`);
  // Проверенный кандидат заменяет файл атомарно с сохранением владельца и режима.
  await replaceWithBackup({candidate: text, backup, expectedOriginalHash: sha256(original)});
  console.log(`${keyword('Готово')}. Проверка: node check-emudhra-certs.mjs --live`);
  console.log(`Для отката: sudo node restore-emudhra-certs.mjs --backup '${backup}'`);
  if (!opts['--include-aaa'] && before.aaa) console.warn('AAA оставлен: это не устраняет альтернативную TLS-цепочку через Sectigo.');
}

// Любая ошибка должна давать ненулевой код, а не сообщать ложный успех.
main().catch(error => {console.error(`${keyword('ERROR', process.stderr)}: ${error.message}`); process.exitCode = 2;});
