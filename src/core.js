/**
 * Core implementation of the columnar transposition cipher.
 *
 * Interpretation chosen (documented in README.md):
 *   - The plaintext is padded to a multiple of the keyword length using the
 *     ASCII period ('.') before being written into the grid. Padding makes the
 *     ciphertext length a clean multiple of the column count, so decryption
 *     can split the ciphertext into equal-length chunks unambiguously.
 *   - Column order is derived from the keyword by stable ranking: columns
 *     are ordered by their keyword character's char code, and ties keep
 *     their original left-to-right order. This is the most common textbook
 *     definition and avoids relying on a specific language's sort stability.
 *   - Ciphertext is read column by column in that derived order.
 *   - Only the printable ASCII range (0x20-0x7E) is accepted for both the
 *     text and the keyword. Non-ASCII or control characters are rejected so
 *     the cipher behaves deterministically on every byte of the input.
 */

const PRINTABLE_MIN = 0x20;
const PRINTABLE_MAX = 0x7e;
const PAD_CHAR = '.';

/**
 * Validates that every character of `s` is printable ASCII (0x20-0x7e).
 * Rejecting control characters and non-ASCII keeps the cipher fully
 * deterministic and makes padding behaviour predictable.
 *
 * @param {string} s
 * @param {string} label - Used in error messages to identify the input.
 * @returns {void}
 * @throws {RangeError} If any character falls outside the printable range.
 */
function assertPrintableAscii(s, label) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < PRINTABLE_MIN || code > PRINTABLE_MAX) {
      throw new RangeError(
        `${label} must contain only printable ASCII characters; ` +
        `found character with code ${code} at position ${i}.`
      );
    }
  }
}

/**
 * Computes the column read order from a keyword via stable ranking.
 *
 * Lower char codes are read first; ties preserve original left-to-right
 * position. We do this with an explicit index map rather than relying on a
 * particular sort implementation's stability, so the result is identical
 * across runtimes.
 *
 * @param {string} keyword
 * @returns {number[]} Array of length `keyword.length`; element at position
 *   `r` is the source column index that is the `r`-th column to be read.
 */
function columnOrder(keyword) {
  const codes = [];
  for (let i = 0; i < keyword.length; i++) {
    codes.push(keyword.charCodeAt(i));
  }
  const indices = codes.map((_, i) => i);
  indices.sort((a, b) => {
    if (codes[a] !== codes[b]) return codes[a] - codes[b];
    return a - b; // stable tie-break on original position
  });
  return indices;
}

/**
 * Pads `text` on the right with `PAD_CHAR` until its length is a multiple of
 * `cols`. Padding to an exact grid multiple is what lets decryption recover
 * the row layout from the ciphertext length alone.
 *
 * @param {string} text
 * @param {number} cols
 * @returns {string}
 */
function padToGrid(text, cols) {
  const remainder = text.length % cols;
  if (remainder === 0) return text;
  const padCount = cols - remainder;
  return text + PAD_CHAR.repeat(padCount);
}

/**
 * Enciphers `plaintext` using a columnar transposition keyed by `keyword`.
 *
 * @param {string} plaintext
 * @param {string} keyword
 * @returns {string}
 * @throws {RangeError} If inputs are empty or contain non-printable-ASCII.
 */
export function encipher(plaintext, keyword) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('plaintext must be a string');
  }
  if (typeof keyword !== 'string') {
    throw new TypeError('keyword must be a string');
  }
  if (keyword.length === 0) {
    throw new RangeError('keyword must not be empty');
  }
  assertPrintableAscii(plaintext, 'plaintext');
  assertPrintableAscii(keyword, 'keyword');

  const cols = keyword.length;
  const padded = padToGrid(plaintext, cols);
  const rows = padded.length / cols;
  const order = columnOrder(keyword);

  let out = '';
  for (let r = 0; r < order.length; r++) {
    const col = order[r];
    for (let row = 0; row < rows; row++) {
      out += padded.charAt(row * cols + col);
    }
  }
  return out;
}

/**
 * Deciphers `ciphertext` that was produced by `encipher` with the same
 * `keyword`. Any trailing pad characters in the recovered plaintext are
 * stripped, because they are an artifact of the padding step.
 *
 * @param {string} ciphertext
 * @param {string} keyword
 * @returns {string}
 * @throws {RangeError} If inputs are empty, contain non-printable-ASCII, or
 *   the ciphertext length is not a multiple of the keyword length.
 */
export function decipher(ciphertext, keyword) {
  if (typeof ciphertext !== 'string') {
    throw new TypeError('ciphertext must be a string');
  }
  if (typeof keyword !== 'string') {
    throw new TypeError('keyword must be a string');
  }
  if (keyword.length === 0) {
    throw new RangeError('keyword must not be empty');
  }
  assertPrintableAscii(ciphertext, 'ciphertext');
  assertPrintableAscii(keyword, 'keyword');

  const cols = keyword.length;
  if (ciphertext.length % cols !== 0) {
    throw new RangeError(
      `ciphertext length (${ciphertext.length}) must be a multiple of ` +
      `keyword length (${cols}); the input is not a valid ciphertext for ` +
      `this keyword.`
    );
  }

  const rows = ciphertext.length / cols;
  const order = columnOrder(keyword);

  // Distribute ciphertext characters back into their source columns. The
  // `r`-th chunk of `rows` characters corresponds to the column at
  // `order[r]` in the original grid.
  const grid = new Array(rows * cols);
  for (let r = 0; r < order.length; r++) {
    const col = order[r];
    for (let row = 0; row < rows; row++) {
      grid[row * cols + col] = ciphertext.charAt(r * rows + row);
    }
  }

  let plaintext = grid.join('');
  // Strip the padding we added during encipher. Only trailing PAD_CHAR
  // characters are removed, so genuine trailing periods in the original
  // message are preserved up to the padding length.
  while (plaintext.length > 0 && plaintext.charAt(plaintext.length - 1) === PAD_CHAR) {
    plaintext = plaintext.slice(0, -1);
  }
  return plaintext;
}
