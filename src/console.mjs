// Окрашиваем только известные ключевые слова в момент печати, не данные отчёта.
const COLORS = new Map([
  ['REJECTED', 32],
  ['UNKNOWN', 33],
  ['ACCEPTED', 31],
  ['DRY-RUN', 33],
  ['ERROR', 31],
  ['Готово', 32],
  ['REVIEW', 33],
  ['COMPROMISED', 31],
]);

const TONES = {green: 32, yellow: 33, red: 31};

// Проверяем конкретный поток: stdout и stderr могут перенаправляться независимо.
// Без TTY или при NO_COLOR ANSI-коды не попадают в файлы и shell-конвейеры.
export function colorText(text, tone, stream = process.stdout) {
  const color = TONES[tone];
  if (!color || !stream.isTTY || Object.hasOwn(process.env, 'NO_COLOR') || process.env.TERM === 'dumb') return text;
  return `\u001b[${color}m${text}\u001b[39m`;
}

export function keyword(word, stream = process.stdout) {
  const tone = Object.keys(TONES).find(name => TONES[name] === COLORS.get(word));
  return colorText(word, tone, stream);
}

// Наличие корня требует анализа, но не доказывает компрометацию самого корня.
// Нулевые счётчики не выделяем, чтобы внимание привлекали только находки.
export function rootCount(name, count, stream = process.stdout) {
  const text = `${name}=${count}`;
  return count > 0 ? colorText(text, 'yellow', stream) : text;
}
