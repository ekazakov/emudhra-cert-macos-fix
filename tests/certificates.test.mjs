// Тесты выполняются без root и не обращаются к /etc/ssl/cert.pem.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {parseCertificates, summarize, removeRoots, onlyRootsDiffer, TARGET_ROOTS, ROOT_HEADERS, COMPROMISED} from '../src/certificates.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'emudhra-fixture-'));
const pem = (name, cn) => {
  const dest = path.join(tmp, `${name}.crt`);
  execFileSync('openssl', ['req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(tmp, `${name}.key`), '-out', dest, '-days', '1', '-subj', `/CN=${cn}`], {stdio: 'ignore'});
  return fs.readFileSync(dest, 'utf8');
};
const em = pem('em', 'emSign ECC Root CA - G3');
const aaa = pem('aaa', 'AAA Certificate Services');
const other = pem('other', 'Safe Unrelated CA');
const fingerprint = certificate => new X509Certificate(certificate).fingerprint256.replaceAll(':', '').toUpperCase();
const saved = [...TARGET_ROOTS];
TARGET_ROOTS.clear();
TARGET_ROOTS.set(fingerprint(em), 'emSign ECC Root CA - G3');
TARGET_ROOTS.set(fingerprint(aaa), 'AAA Certificate Services');
const source = `${ROOT_HEADERS.get('emSign ECC Root CA - G3')}\n${em}${ROOT_HEADERS.get('AAA Certificate Services')}\n${aaa}=== /CN=Safe Unrelated CA\n${other}`;

test('parseCertificates detects three certificates and rejects partial PEM', () => {
  assert.equal(parseCertificates(source).length, 3);
  assert.throws(() => parseCertificates(source + '\n-----BEGIN CERTIFICATE-----\ninvalid'));
});

test('removeRoots removes exact emSign section and preserves other roots', () => {
  const {text, after, removed} = removeRoots(source);
  assert.deepEqual(removed, ['emSign ECC Root CA - G3']);
  assert.equal(after.total, 2);
  assert.equal(after.aaa, 1);
  assert.ok(text.includes('Safe Unrelated CA'));
  assert.ok(!text.includes('emSign ECC Root CA - G3'));
});

test('removeRoots with --include-aaa removes both, and is idempotent', () => {
  const once = removeRoots(source, {includeAAA:true});
  assert.equal(once.after.total, 1);
  assert.equal(once.after.em, 0);
  assert.equal(once.after.aaa, 0);
  assert.equal(removeRoots(once.text, {includeAAA:true}).removed.length, 0);
});

test('restore guard accepts root-only difference and rejects unrelated edit', () => {
  const mitigated = removeRoots(source, {includeAAA:true}).text;
  assert.equal(onlyRootsDiffer(mitigated, source), true);
  assert.equal(onlyRootsDiffer(mitigated + '# updated by Apple\n', source), false);
});

test('unknown or duplicate section layout cannot delete unrelated certificates', () => {
  assert.throws(() => removeRoots(source.replace(ROOT_HEADERS.get('emSign ECC Root CA - G3'), '=== /CN=Other')), /заголовок/);
  assert.throws(() => removeRoots(source + ROOT_HEADERS.get('emSign ECC Root CA - G3') + '\n' + em), /дубликаты/);
});

test('known compromised fingerprints data contains sixteen unique entries', () => {
  assert.equal(COMPROMISED.size, 16);
  for (const key of COMPROMISED.keys()) assert.match(key, /^[A-F0-9]{64}$/);
});

test.after(() => {
  TARGET_ROOTS.clear();
  for (const [key, value] of saved) TARGET_ROOTS.set(key,value);
  fs.rmSync(tmp, {recursive:true,force:true});
});
