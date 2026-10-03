Columnar transposition cipher: encipher and decipher text by writing it into a grid row by row and reading columns off in an order determined by a keyword.

Usage:

```js
import { encipher, decipher } from './src/index.js';

const ct = encipher('WEAREDISCOVEREDFLEEATONCE', 'ZEBRA');
// => 'EODAEEIELOARSRENWDVFTRCEEC'
const pt = decipher(ct, 'ZEBRA');
// => 'WEAREDISCOVEREDFLEEATONCE'
```

Exports `encipher(plaintext, keyword)` and `decipher(ciphertext, keyword)` from `src/index.js`. Both are pure functions; the module has no state and no third-party dependencies.

Why this exists: a small, dependency-free primitive for the classical columnar transposition cipher, suitable for teaching, puzzles, or as a building block in a larger exercise. The trade-off is simplicity over security — this is a historical cipher and is trivially breakable.

Interpretation choices (stated plainly so there are no surprises):
- The keyword determines column order by stable ranking of character codes. Equal characters keep their left-to-right order.
- Plaintext is right-padded with `.` to fill the grid. `decipher` strips trailing `.` characters. A plaintext that genuinely ends in `.` will lose those trailing periods on decipher, because they are indistinguishable from padding. This is the unavoidable ambiguity of padded columnar transposition.
- Only printable ASCII (0x20–0x7e) is accepted in both text and keyword; other inputs throw `RangeError`.

Awkward edge: because of the padding scheme, never trust a recovered plaintext's trailing periods. If your message may end in `.`, use a different delimiter or length-prefix in a higher layer.
