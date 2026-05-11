import { describe, expect, it } from 'vitest';

describe('scaffold smoke', () => {
  it('vitest runs in this workspace project', () => {
    expect(1 + 1).toBe(2);
  });

  it('TypeScript types are available', () => {
    const value: number = 42;
    expect(typeof value).toBe('number');
  });
});
