#!/usr/bin/env node
// Устанавливаем пользовательский macOS LaunchAgent вместо cron/фонового daemon.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { $ } from 'zx';
import { requireMac, parseArgs } from './src/system.mjs';

// Конкретный label используется для обновления и удаления нашей задачи.
const LABEL = 'local.emudhra.certificate-audit';
const SOURCE = path.dirname(fileURLToPath(import.meta.url));
const HOME = os.homedir();
const APP = path.join(HOME, 'Library', 'Application Support', 'eMudhraAudit');
const PLIST = path.join(HOME, 'Library', 'LaunchAgents', `${LABEL}.plist`);

// XML-экранирование защищает конфигурацию при пробелах и специальных символах.
export const xml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');

// Формируем валидный plist средствами JS, без shell heredoc, sed и awk.
export function createPlist({node, runner, hour, minute, liveAll = false}) {
  const args = [node, runner, ...(liveAll ? ['--live-all'] : [])];
  const stdout = path.join(HOME, 'Library', 'Logs', 'emudhra-launchd.out.log');
  const stderr = path.join(HOME, 'Library', 'Logs', 'emudhra-launchd.err.log');
  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0"><dict>\n` +
    `  <key>Label</key><string>${xml(LABEL)}</string>\n` +
    `  <key>ProgramArguments</key><array>${args.map(a => `<string>${xml(a)}</string>`).join('')}</array>\n` +
    `  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>${hour}</integer><key>Minute</key><integer>${minute}</integer></dict>\n` +
    `  <key>StandardOutPath</key><string>${xml(stdout)}</string>\n` +
    `  <key>StandardErrorPath</key><string>${xml(stderr)}</string>\n` +
    `</dict></plist>\n`;
}

// Проверяем часы без опасной арифметики Bash (включая 08 и 09).
export function parseTime(value) {
  if (!/^\d{2}:\d{2}$/.test(value)) throw new Error('Ожидается время HH:MM');
  const [hour, minute] = value.split(':').map(Number);
  if (hour > 23 || minute > 59) throw new Error('Некорректное время: используйте 00:00–23:59');
  return {hour, minute};
}

// Запрашиваем launchctl напрямую из zx, а не создаём shell-скрипты для планирования.
async function launchctl(...args) {
  // Раздельные ветки предотвращают ошибку передачи массива аргументов как одного параметра.
  const output = await $({quiet: true, nothrow: true, timeout: 15000})`/bin/launchctl ${args}`;
  return output;
}

// Отсутствующая служба допустима; ошибки доступа и GUI-domain не скрываем.
export async function stopService(service, run = launchctl) {
  const status = await run('print', service);
  if (status.exitCode === 113 && status.stderr.includes('Could not find service')) return;
  if (status.exitCode !== 0) throw new Error(`launchctl print: ${status.stderr.trim()}`);
  const stopped = await run('bootout', service);
  if (stopped.exitCode !== 0) throw new Error(`launchctl bootout: ${stopped.stderr.trim()}`);
}

// Логика установки и удаления не требует sudo и не пишет в системный Keychain.
async function main() {
  const opts = parseArgs(process.argv.slice(2), {'--time': 'value', '--live-all': true, '--uninstall': true, '--help': true});
  if (opts['--help']) {console.log('node install-emudhra-monitor.mjs [--time 09:00] [--live-all] [--uninstall]'); return;}
  requireMac();
  if (process.getuid?.() === 0) throw new Error('Запускайте установщик от обычного пользователя, без sudo');
  const domain = `gui/${process.getuid()}`;
  const service = `${domain}/${LABEL}`;
  if (opts['--uninstall']) {
    await stopService(service);
    await fs.rm(PLIST, {force: true});
    console.log('Расписание удалено. Скрипты и журналы сохранены.');
    return;
  }
  const {hour, minute} = parseTime(opts['--time'] ?? '09:00');
  // Фиксируем абсолютный Node, чтобы launchd не зависел от PATH пользователя.
  const node = process.execPath;
  // Останавливаем старый монитор до обновления модулей, исключая смешение версий.
  await fs.access(path.join(SOURCE, 'node_modules', 'zx'));
  await stopService(service);
  await fs.mkdir(APP, {recursive: true, mode: 0o700});
  await fs.mkdir(path.dirname(PLIST), {recursive: true});
  await fs.mkdir(path.join(HOME, 'Library', 'Logs'), {recursive: true});
  // Копируем только JS-скрипты и их библиотеку, без sudo и private certificates.
  await fs.mkdir(path.join(APP, 'src'), {recursive: true});
  for (const file of ['check-emudhra-certs.mjs', 'run-emudhra-monitor.mjs', 'src/certificates.mjs', 'src/system.mjs', 'src/console.mjs']) {
    const target = path.join(APP, file);
    await fs.copyFile(path.join(SOURCE, file), target);
    await fs.chmod(target, 0o700);
  }
  // Библиотека zx должна быть доступна установленным JS-файлам в APP.
  const modulePath = path.join(SOURCE, 'node_modules');
  try {
    await fs.access(path.join(modulePath, 'zx'));
  } catch { throw new Error('Сначала выполните npm install в папке проекта'); }
  // Копируем ВСЕ установленные npm-зависимости (zx использует и вложенные пакеты).
  // Нельзя копировать только папку zx: это может сломать imports при работе launchd.
  const targetModules = path.join(APP, 'node_modules');
  if (path.resolve(modulePath) !== path.resolve(targetModules)) {
    await fs.rm(targetModules, {recursive: true, force: true});
    await fs.cp(modulePath, targetModules, {recursive: true, force: true});
  }
  // Копия делает LaunchAgent независимым от перемещения исходного проекта.
  const plistText = createPlist({node, runner: path.join(APP, 'run-emudhra-monitor.mjs'), hour, minute, liveAll: Boolean(opts['--live-all'])});
  await fs.writeFile(PLIST, plistText, {mode: 0o600});
  const validation = await $({quiet: true, nothrow: true})`/usr/bin/plutil -lint ${PLIST}`;
  if (validation.exitCode !== 0) throw new Error(`Некорректный plist: ${validation.stderr}`);
  const installed = await launchctl('bootstrap', domain, PLIST);
  if (installed.exitCode !== 0) throw new Error(`launchctl bootstrap: ${installed.stderr.trim()}`);
  console.log(`Монитор установлен: каждый день в ${opts['--time'] ?? '09:00'}.`);
  console.log(`Тест: "${node}" "${path.join(APP, 'run-emudhra-monitor.mjs')}" --test-notification`);
  console.log(`Запуск сейчас: launchctl kickstart -k ${service}`);
}

// Системная ошибка установки должна завершаться статусом 2 без ложного успеха.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {console.error(`ERROR: ${error.message}`); process.exitCode = 2;});
}
