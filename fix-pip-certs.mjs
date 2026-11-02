#!/usr/bin/env node
// Настраиваем pip текущего пользователя, без sudo и записи в Xcode.
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {SYSTEM_BUNDLE, readBundle, summarize} from './src/certificates.mjs';
import {requireMac, parseArgs} from './src/system.mjs';
import {keyword, rootCount} from './src/console.mjs';
import {pipUserConfigPaths, fixPipUserConfig, verifyPipUserConfig, checkPipEnvironment} from './src/pip.mjs';

async function main() {
  const opts = parseArgs(process.argv.slice(2), {'--dry-run': true, '--help': true});
  if (opts['--help']) { console.log('node fix-pip-certs.mjs [--dry-run]'); return; }
  requireMac();
  if (process.getuid?.() === 0) throw new Error('Запускайте от обычного пользователя, без sudo: изменяется пользовательский pip.conf');
  checkPipEnvironment(process.env,{dryRun:Boolean(opts['--dry-run'])});
  const bundle = summarize(await readBundle(SYSTEM_BUNDLE));
  console.log(`Системный bundle: ${rootCount('emSign', bundle.em)}, ${rootCount('AAA', bundle.aaa)}`);
  if (bundle.em || bundle.aaa || bundle.intermediates.length) {
    console.warn(`[${keyword('REVIEW', process.stderr)}] В системном bundle остались целевые CA. Перенаправление pip само по себе их не блокирует.`);
  }
  const {target,otherFiles} = pipUserConfigPaths();
  console.log(`Пользовательский pip.conf: ${target}`);
  const result = await fixPipUserConfig({target,otherFiles,dryRun:Boolean(opts['--dry-run'])});
  for (const warning of result.warnings) console.warn(`[${keyword('REVIEW', process.stderr)}] ${warning}`);
  if (!opts['--dry-run']) {
    if (result.backup) console.log(`Резервная копия: ${result.backup}`);
    verifyPipUserConfig();
  }
  if (!result.changed) console.log('global.cert уже указывает на системный bundle; изменений нет.');
  else if (opts['--dry-run']) {
    console.log(`${keyword('DRY-RUN')}: будет задано [global] cert = ${SYSTEM_BUNDLE}; файлы не записывались.`);
  } else {
    console.log(`${keyword('Готово')}. pip подтвердил global.cert = ${SYSTEM_BUNDLE}.`);
  }
  console.log('Настройка относится к pip текущего пользователя, включая совместимые pip3, venv и Homebrew. Опции команд и настройки отдельных окружений могут её переопределять.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {console.error(`${keyword('ERROR', process.stderr)}: ${error.message}`); process.exitCode = 2;});
}
