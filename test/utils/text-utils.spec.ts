import { describe, expect, it } from 'vitest';
import { linebrk, trimSurroundingText } from '../../src/utils/text-utils.js';

describe('linebrk', () => {
  it('returns the input unchanged when shorter than maxLen', () => {
    expect(linebrk('abc', 10)).toBe('abc');
  });

  it('returns the input unchanged when length equals maxLen', () => {
    expect(linebrk('abcde', 5)).toBe('abcde');
  });

  it('inserts a newline at every maxLen boundary', () => {
    expect(linebrk('abcdefghij', 3)).toBe('abc\ndef\nghi\nj');
  });

  it('does not emit a trailing newline when input length is a multiple of maxLen', () => {
    expect(linebrk('abcdef', 3)).toBe('abc\ndef');
  });

  it('returns empty string for empty input', () => {
    expect(linebrk('', 4)).toBe('');
  });

  it('handles maxLen = 1 (one char per line)', () => {
    expect(linebrk('abc', 1)).toBe('a\nb\nc');
  });
});

describe('trimSurroundingText', () => {
  const OPEN = '<<BEGIN>>';
  const CLOSE = '<<END>>';

  describe('boundary conditions', () => {
    it('extracts content between first opening and first closing', () => {
      expect(trimSurroundingText(`prefix${OPEN}body${CLOSE}suffix`, OPEN, CLOSE)).toBe('body');
    });

    it('returns input verbatim when neither marker is present', () => {
      expect(trimSurroundingText('plain text', OPEN, CLOSE)).toBe('plain text');
    });

    it('keeps only the tail when only the opening is present', () => {
      expect(trimSurroundingText(`prefix${OPEN}tail`, OPEN, CLOSE)).toBe('tail');
    });

    it('returns input verbatim when only closing appears (no preceding opening)', () => {
      // closing without opening: openIdx = -1 → closeIdx not computed → both
      // bounds default to the whole string.
      expect(trimSurroundingText(`head${CLOSE}suffix`, OPEN, CLOSE)).toBe(`head${CLOSE}suffix`);
    });

    it('extracts an empty body when opening and closing are adjacent', () => {
      expect(trimSurroundingText(`${OPEN}${CLOSE}`, OPEN, CLOSE)).toBe('');
    });

    it('uses the first closing after the first opening, not the last', () => {
      const text = `${OPEN}first${CLOSE}middle${CLOSE}tail`;
      expect(() => trimSurroundingText(text, OPEN, CLOSE)).not.toThrow();
      expect(trimSurroundingText(text, OPEN, CLOSE)).toBe('first');
    });
  });

  describe('multi-block rejection', () => {
    it('throws when a second opening appears after the first closing', () => {
      const text = `${OPEN}one${CLOSE}${OPEN}two${CLOSE}`;
      expect(() => trimSurroundingText(text, OPEN, CLOSE)).toThrow(/multiple .* blocks/);
    });

    it('throws even with arbitrary text between the two blocks', () => {
      const text = `${OPEN}one${CLOSE}\n\n# noise here\n\n${OPEN}two${CLOSE}`;
      expect(() => trimSurroundingText(text, OPEN, CLOSE)).toThrow(/multiple .* blocks/);
    });

    it('does not reject when a different opening marker appears after the close', () => {
      // The guard is keyed on the *same* opening string, not any "BEGIN".
      const text = `${OPEN}body${CLOSE}<<BEGIN OTHER>>other body<<END OTHER>>`;
      expect(() => trimSurroundingText(text, OPEN, CLOSE)).not.toThrow();
      expect(trimSurroundingText(text, OPEN, CLOSE)).toBe('body');
    });

    it('does not reject when a second opening appears *before* the first closing', () => {
      // Two opening markers in a row → second one is just part of the body.
      const text = `${OPEN}${OPEN}body${CLOSE}`;
      expect(() => trimSurroundingText(text, OPEN, CLOSE)).not.toThrow();
      expect(trimSurroundingText(text, OPEN, CLOSE)).toBe(`${OPEN}body`);
    });
  });

  describe('arbitrary markers (not PEM)', () => {
    it('works with multi-char generic markers', () => {
      expect(trimSurroundingText('xxx[[start]]payload[[end]]yyy', '[[start]]', '[[end]]')).toBe(
        'payload',
      );
    });

    it('works with single-char markers', () => {
      expect(trimSurroundingText('a<x>b', '<', '>')).toBe('x');
    });
  });
});
