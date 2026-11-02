/**
 * Назначение: проверить логику ежедневного мониторинга и формирования расписания,
 * не устанавливая LaunchAgent и не отправляя реальные уведомления.
 * Основные шаги:
 * 1. Сравнить ключи уведомлений для одинаковых находок в разном порядке.
 * 2. Проверить текст уведомления для чистого, опасного и неопределённого результата.
 * 3. Проверить допустимость времени ежедневного запуска.
 * 4. Проверить XML-экранирование и поля генерируемого plist.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {notificationKey, messageFor} from '../run-emudhra-monitor.mjs';
import {parseTime, xml, createPlist} from '../install-emudhra-monitor.mjs';

test('no repeat alert for same findings regardless of their order', () => {
  const findings = [{type:'REVIEW',source:'Python',detail:'AAA'},{type:'COMPROMISED',source:'SSL',detail:'fingerprint'}];
  assert.deepEqual(notificationKey({exitCode:1,findings}), notificationKey({exitCode:1,findings:[...findings].reverse()}));
});

test('no notification for clean result and correct severity for findings', () => {
  assert.equal(messageFor({exitCode:0,findings:[]}), null);
  assert.match(messageFor({exitCode:1,findings:[{type:'REVIEW'}]}), /корневой/);
  assert.match(messageFor({exitCode:1,findings:[{type:'ACCEPTED'}]}), /TLS/);
  assert.match(messageFor({exitCode:2,findings:[]}), /неполная/);
});

test('time validation rejects invalid hours and minutes', () => {
  assert.deepEqual(parseTime('09:05'), {hour:9,minute:5});
  assert.throws(() => parseTime('24:00'));
  assert.throws(() => parseTime('08:60'));
});

test('xml is escaped and plist contains calendar hour, minute, node path', () => {
  assert.equal(xml(`foo & "bar"`), 'foo &amp; &quot;bar&quot;');
  const plist = createPlist({node:'/Users/A & B/.local/node',runner:'/tmp/run.mjs',hour:9,minute:5,liveAll:true});
  assert.match(plist,/A &amp; B/);
  assert.match(plist,/<integer>9<\/integer>/);
  assert.match(plist,/<integer>5<\/integer>/);
  assert.match(plist, /--live-all/);
});
