// Встроенные модули Node.js заменяют openssl, grep, awk и Python для PEM/X.509.
import { X509Certificate, createHash } from "node:crypto";
import fs from "node:fs/promises";

// Адрес системного списка доверенных корней для штатных CLI macOS.
export const SYSTEM_BUNDLE = "/etc/ssl/cert.pem";

// SHA-256 двух корней именно из списка инцидента: совпадение CN недостаточно.
export const TARGET_ROOTS = new Map([
  [
    "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B",
    "emSign ECC Root CA - G3",
  ],
  [
    "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4",
    "AAA Certificate Services",
  ],
]);

// Список 16 SHA-256 из impacted-intermediates.json (TLS и code-signing).
// Ровно эти сертификаты скомпрометированы; сами корневые CA не скомпрометированы.
export const COMPROMISED = new Map([
  [
    "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838",
    "EM EV TLS CA - G3B / eMudhra",
  ],
  [
    "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B",
    "EM OV TLS CA - G3B / eMudhra",
  ],
  [
    "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493",
    "EM DV TLS CA - G3B / eMudhra",
  ],
  [
    "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3",
    "EM EV TLS CA - G3C / eMudhra",
  ],
  [
    "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F",
    "EM OV TLS CA - G3C / eMudhra",
  ],
  [
    "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19",
    "EM DV TLS CA - G3C / eMudhra",
  ],
  [
    "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512",
    "EM EV TLS CA - G3B / Sectigo",
  ],
  [
    "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699",
    "EM OV TLS CA - G3B / Sectigo",
  ],
  [
    "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE",
    "EM DV TLS CA - G3B / Sectigo",
  ],
  [
    "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F",
    "EM EV TLS CA - G3C / Sectigo",
  ],
  [
    "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489",
    "EM OV TLS CA - G3C / Sectigo",
  ],
  [
    "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72",
    "EM DV TLS CA - G3C / Sectigo",
  ],
  [
    "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4",
    "EM OV CS CA - G3B / eMudhra",
  ],
  [
    "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8",
    "EM OV CS CA - G3B / Sectigo",
  ],
  [
    "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1",
    "EM OV CS CA - G3C / eMudhra",
  ],
  [
    "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD",
    "EM OV CS CA - G3C / Sectigo",
  ],
]);

// Точные заголовки macOS нужны для удаления всей секции, а не одного PEM-блока.
export const ROOT_HEADERS = new Map([
  [
    "emSign ECC Root CA - G3",
    "=== /C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3",
  ],
  [
    "AAA Certificate Services",
    "=== /C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services",
  ],
]);

// Переводим буфер или строку в UTF-8; сертификатные PEM-файлы — текстовые.
const asText = (value) =>
  Buffer.isBuffer(value) ? value.toString("utf8") : String(value);

// Декодируем все PEM-блоки в X509Certificate и обнаруживаем повреждённый ввод.
export function parseCertificates(contents) {
  const text = asText(contents);
  const markers = [...text.matchAll(/-----BEGIN CERTIFICATE-----/g)];
  const ends = [...text.matchAll(/-----END CERTIFICATE-----/g)];
  const blocks = [
    ...text.matchAll(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    ),
  ];
  if (
    !blocks.length ||
    markers.length !== blocks.length ||
    ends.length !== blocks.length
  ) {
    throw new Error(
      "PEM: отсутствуют сертификаты или обнаружены неполные блоки",
    );
  }
  return blocks.map((match) => {
    const pem = match[0];
    const certificate = new X509Certificate(pem);
    return {
      pem,
      start: match.index,
      end: match.index + pem.length,
      subject: certificate.subject,
      fingerprint: certificate.fingerprint256.replaceAll(":", "").toUpperCase(),
    };
  });
}

// Отдельный путь читает реальные файлы без shell и без временного вывода openssl.
export async function readBundle(file) {
  const handle = await fs.open(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  try {
    if (!(await handle.stat()).isFile())
      throw new Error(`Не обычный файл: ${file}`);
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

// Возвращаем число целей и точные промежуточные сертификаты по SHA-256.
export function summarize(text) {
  const certificates = parseCertificates(text);
  const em = certificates.filter(
    (c) => c.fingerprint === [...TARGET_ROOTS.keys()][0],
  ).length;
  const aaa = certificates.filter(
    (c) => c.fingerprint === [...TARGET_ROOTS.keys()][1],
  ).length;
  const intermediates = certificates.flatMap((c) =>
    COMPROMISED.has(c.fingerprint)
      ? [{ name: COMPROMISED.get(c.fingerprint), sha256: c.fingerprint }]
      : [],
  );
  return { total: certificates.length, em, aaa, intermediates };
}

// Обеспечиваем точность удаления: только Apple-заголовки и SHA-256 нужных корней.
export function removeRoots(text, { includeAAA = false } = {}) {
  const certificates = parseCertificates(text);
  const selected = new Set(
    includeAAA ? [...TARGET_ROOTS.keys()] : [[...TARGET_ROOTS.keys()][0]],
  );
  const removed = certificates.filter((c) => selected.has(c.fingerprint));
  if (new Set(removed.map((c) => c.fingerprint)).size !== removed.length) {
    throw new Error(
      "Обнаружены дубликаты целевых корней; автоматическое изменение запрещено",
    );
  }
  // Секции Apple содержат заголовок ===, необязательные строки ### и один PEM.
  const sections = [...text.matchAll(/^=== .*$/gm)].map((m) => ({
    start: m.index,
    header: m[0],
  }));
  let result = text;
  const ranges = [];
  for (const root of removed) {
    const name = TARGET_ROOTS.get(root.fingerprint);
    const header = ROOT_HEADERS.get(name);
    const sectionIndex = sections.findIndex(
      (section, i) =>
        section.header === header &&
        section.start < root.start &&
        (sections[i + 1]?.start ?? text.length) > root.end,
    );
    if (sectionIndex === -1)
      throw new Error(`Не найден точный заголовок Apple для ${name}`);
    const section = sections[sectionIndex];
    const next = sections[sectionIndex + 1]?.start ?? text.length;
    // Запрещаем удалять секцию с несколькими сертификатами или скрытыми PEM.
    if (
      certificates.filter((c) => c.start >= section.start && c.end <= next)
        .length !== 1
    ) {
      throw new Error(`Неожиданная структура секции ${name}`);
    }
    ranges.push({ start: section.start, end: next });
  }
  // Отсекаем секции с конца, чтобы индексы предыдущих частей текста не сдвигались.
  for (const { start, end } of ranges.sort((a, b) => b.start - a.start)) {
    result = result.slice(0, start) + result.slice(end);
  }
  const after = summarize(result);
  if (
    after.total !== certificates.length - removed.length ||
    after.em !== 0 ||
    (includeAAA && after.aaa !== 0)
  ) {
    throw new Error(
      "После удаления количество сертификатов или целевых CA не совпало",
    );
  }
  return {
    text: result,
    removed: removed.map((root) => TARGET_ROOTS.get(root.fingerprint)),
    after,
  };
}

// Восстановление без --force безопасно, если файловые различия — только эти секции.
export function onlyRootsDiffer(current, backup) {
  return (
    removeRoots(current, { includeAAA: true }).text ===
    removeRoots(backup, { includeAAA: true }).text
  );
}

// --force разрешает другие различия, но никогда не обходит валидацию X.509.
export function validateRestore(current, backup, { force = false } = {}) {
  parseCertificates(current);
  parseCertificates(backup);
  let safe = false;
  try {
    safe = onlyRootsDiffer(current, backup);
  } catch {
    /* Неизвестную структуру разрешает только явный --force. */
  }
  if (!safe && !force)
    throw new Error(
      "Обнаружены другие изменения bundle (возможно обновление macOS): отказ. --force допускает откат обновлений",
    );
  return { safe, candidate: backup };
}

// Создаём SHA-256 всего файла, чтобы проверять резервирование и установку.
export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");
