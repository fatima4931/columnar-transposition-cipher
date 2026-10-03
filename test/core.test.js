import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { encipher, decipher } from '../src/core.js';

describe('columnar transposition cipher', () => {
  describe('round-trip', () => {
    it('round-trips a message shorter than the keyword', () => {
      const plain = 'HI';
      const keyword = 'ZEBRA';
      assert.equal(decipher(encipher(plain, keyword), keyword), plain);
    });

    it('round-trips a message longer than the keyword with no padding needed', () => {
      const plain = 'WEAREDISCOVEREDFLEEATONCE';
      const keyword = 'ZEBRA';
      assert.equal(plain.length % keyword.length, 0);
      assert.equal(decipher(encipher(plain, keyword), keyword), plain);
    });

    it('round-trips a message that requires padding', () => {
      const plain = 'ATTACKATDAWN';
      const keyword = 'ZEBRA';
      assert.notEqual(plain.length % keyword.length, 0);
      assert.equal(decipher(encipher(plain, keyword), keyword), plain);
    });

    it('round-trips a message containing all printable ASCII chars', () => {
      let plain = '';
      for (let c = 0x20; c <= 0x7e; c++) plain += String.fromCharCode(c);
      const keyword = 'KEY';
      assert.equal(decipher(encipher(plain, keyword), keyword), plain);
    });

    it('round-trips a one-character message', () => {
      assert.equal(decipher(encipher('X', 'ZEBRA'), 'ZEBRA'), 'X');
    });

    it('round-trips with a single-character keyword', () => {
      // A single-column transposition is the identity cipher after padding.
      const plain = 'HELLOWORLD';
      assert.equal(decipher(encipher(plain, 'K'), 'K'), plain);
    });

    it('round-trips with a keyword whose chars are all identical', () => {
      // All columns tie; stable ranking keeps natural left-to-right order.
      const plain = 'COLUMNARTRANSPOSITION';
      const keyword = 'AAAA';
      assert.equal(decipher(encipher(plain, keyword), keyword), plain);
    });
  });

  describe('known ciphertext', () => {
    it('produces the expected ciphertext for a textbook example', () => {
      // Grid (cols=5, keyword 'ZEBRA', read order A,B,E,R,Z -> cols 4,2,1,3,0):
      //   W E A R E
      //   D I S C O
      //   V E R E D
      //   F L E E A
      //   T O N C E
      // Reading columns in rank order of ZEBRA:
      //   col4 EODAE  col2 ASREN  col1 EIELO  col3 RCEEC  col0 WDVFT
      //   -> 'EODAE' + 'ASREN' + 'EIELO' + 'RCEEC' + 'WDVFT'
      const plain = 'WEAREDISCOVEREDFLEEATONCE';
      const keyword = 'ZEBRA';
      const expected = 'EODAEASRENEIELORCEECWDVFT';
      assert.equal(encipher(plain, keyword), expected);
      assert.equal(decipher(expected, keyword), plain);
    });
  });

  describe('input validation', () => {
    it('throws RangeError on empty keyword for encipher', () => {
      assert.throws(() => encipher('HELLO', ''), RangeError);
    });

    it('throws RangeError on empty keyword for decipher', () => {
      assert.throws(() => decipher('HELLO', ''), RangeError);
    });

    it('throws TypeError on non-string plaintext', () => {
      assert.throws(() => encipher(123, 'ZEBRA'), TypeError);
    });

    it('throws TypeError on non-string keyword', () => {
      assert.throws(() => encipher('HELLO', 123), TypeError);
    });

    it('throws RangeError when plaintext contains a control character', () => {
      assert.throws(() => encipher('HELLO\tWORLD', 'ZEBRA'), RangeError);
    });

    it('throws RangeError when plaintext contains a non-ASCII character', () => {
      assert.throws(() => encipher('CAFÉ', 'ZEBRA'), RangeError);
    });

    it('throws RangeError when keyword contains a non-printable character', () => {
      assert.throws(() => encipher('HELLO', 'ZEB\nRA'), RangeError);
    });
  });

  describe('decipher length check', () => {
    it('throws RangeError when ciphertext length is not a multiple of keyword length', () => {
      // length 6 is not a multiple of keyword length 5
      assert.throws(() => decipher('ABCDEF', 'ZEBRA'), RangeError);
    });
  });

  describe('padding behaviour', () => {
    it('pads short plaintext to a full grid and strips padding on decipher', () => {
      const plain = 'GO';
      const keyword = 'ZEBRA';
      // Enciphered length must be a multiple of 5.
      const ct = encipher(plain, keyword);
      assert.equal(ct.length % keyword.length, 0);
      assert.equal(decipher(ct, keyword), plain);
    });

    it('preserves genuine trailing periods up to the padding length', () => {
      // A plaintext ending in a period is indistinguishable from padding
      // once ciphered, so decipher strips it. This documents that
      // behaviour rather than pretending to recover it.
      const plain = 'END.';
      const keyword = 'ZEBRA';
      const ct = encipher(plain, keyword);
      assert.equal(decipher(ct, keyword), 'END');
    });
  });
});
