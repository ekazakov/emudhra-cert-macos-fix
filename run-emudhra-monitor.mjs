#!/usr/bin/env node
// Запускаем ежедневный аудит и показываем уведомления только при новых находках.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { $ } from 'zx';
import { parseArgs, requireMac } from './src/system.mjs';

// Все пути вычисляем относительно установленного JS-файла, не от cwd launchd.
const APP = path.dirname(fileURLToPath(import.meta.url));
const STATE = path.join(APP, 'state');
const LOG = path.join(os.homedir(), 'Library', 'Logs', 'emudhra-certificate-audit.log');
const CURRENT_REPORT = path.join(STATE, 'last-report.json');
const PREVIOUS = path.join(STATE, 'last-notification-state.json');

// Текст уведомления передаём osascript как отдельный аргумент (без инъекций).
async function notify(message) {
  const result = await $({quiet: true, nothrow: true, timeout: 10000})`/usr/bin/osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "eMudhra Certificate Audit"' -e 'end run' ${message}`;
  if (result.exitCode !== 0) throw new Error(`Notification Center: ${result.stderr.trim()}`);
}

// Повторение одинаковых результатов не вызывает новое уведомление каждый день.
export function notificationKey(report) {
  return [
    ...new Set((report.findings ?? []).map(x => `${x.type}|${x.source}|${x.detail}`)),
    ...new Set((report.unknown ?? []).map(x => `UNKNOWN|${x.source}`)),
  ].sort();
}

// Состояние подтверждаем после успешной доставки: при сбое повторяем в следующий раз.
export async function deliverNotification(report, previous, {send, save}) {
  const current = notificationKey(report);
  if (JSON.stringify(previous) === JSON.stringify(current)) return;
  const message = messageFor(report);
  if (message) await send(message);
  await save(current);
}

// Выбираем корректный текст, не выдавая наличие корня за доказательство атаки.
export function messageFor(report) {
  if (report.findings.some(f => f.type === 'ACCEPTED')) return 'Тестовая TLS-цепочка принята. Проверьте журнал eMudhra.';
  if (report.findings.some(f => f.type === 'COMPROMISED')) return 'Найден точный отпечаток скомпрометированного CA. Проверьте журнал.';
  if (report.exitCode === 1) return `В хранилище обнаружен проверяемый корневой CA. Это не доказательство уязвимости.${report.unknown?.length ? ' Проверка также неполная; посмотрите журнал.' : ''}`;
  if (report.exitCode === 2) return 'Проверка eMudhra неполная или завершилась с ошибкой. Посмотрите журнал.';
  return null;
}

// Ограничиваем размер лога; одну предыдущую копию сохраняем для диагностики.
async function rotateLog() {
  try {
    if ((await fs.stat(LOG)).size > 2 * 1024 * 1024) await fs.rename(LOG, `${LOG}.1`);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}

// Записываем JSON атомарно: состояние не будет частично обновлено при сбое.
async function atomicJSON(filename, value) {
  const temp = `${filename}.${process.pid}.tmp`;
  try { await fs.writeFile(temp, JSON.stringify(value, null, 2), {mode: 0o600, flag: 'wx'}); await fs.rename(temp, filename); }
  finally { await fs.rm(temp, {force: true}); }
}

// Монитор использует zx только для osascript; сам checker запускаем в том же Node.
async function main() {
  const opts = parseArgs(process.argv.slice(2), {'--test-notification': true, '--live-all': true});
  requireMac();
  if (opts['--test-notification']) { await notify('Тестовое уведомление: ежедневный аудит настроен.'); return; }
  await fs.mkdir(STATE, {recursive: true, mode: 0o700});
  await fs.mkdir(path.dirname(LOG), {recursive: true});
  await rotateLog();
  // Импорт исключает второй Node-процесс и надёжнее передачи JSON через shell.
  const {runAudit} = await import('./check-emudhra-certs.mjs');
  const report = (await runAudit({liveMode: opts['--live-all'] ? 'all' : 'curl'})).toJSON();
  await atomicJSON(CURRENT_REPORT, report);
  await fs.appendFile(LOG, `\n=== ${new Date().toISOString()} exit=${report.exitCode} ===\n${JSON.stringify(report, null, 2)}\n`);
  let previous = null;
  try { previous = JSON.parse(await fs.readFile(PREVIOUS, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') console.warn(`Предыдущее состояние недоступно: ${error.message}`); }
  try { await deliverNotification(report, previous, {send: notify, save: state => atomicJSON(PREVIOUS, state)}); }
  catch (error) {
    await fs.appendFile(LOG, `[NOTIFICATION ERROR] ${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  process.exitCode = report.exitCode;
}

// Не скрываем ошибку запуска: отчёт launchd должен сигнализировать о сбое.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {console.error(`ERROR: ${error.message}`); process.exitCode = 2;});
}
