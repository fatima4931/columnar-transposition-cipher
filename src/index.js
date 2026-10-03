/**
 * Public entry point for the columnar-transposition-cipher library.
 *
 * Re-exports the cipher primitives so consumers depend on `index.js` and
 * stay decoupled from the internal module layout.
 */
export { encipher, decipher } from './core.js';
