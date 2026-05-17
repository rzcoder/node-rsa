/** Insert `\n` every `maxLen` chars. */
export function linebrk(str: string, maxLen: number): string {
  let out = '';
  let i = 0;
  while (i + maxLen < str.length) {
    out += `${str.substring(i, i + maxLen)}\n`;
    i += maxLen;
  }
  return out + str.substring(i);
}

/**
 * Extract the body between `opening` and `closing` markers. Returns the
 * input unchanged if markers aren't found. Throws if a second `opening`
 * appears after the first `closing` (multi-block input — RFC 7468 §3
 * forbids ambiguity for PEM-style inputs).
 */
export function trimSurroundingText(data: string, opening: string, closing: string): string {
  let start = 0;
  let end = data.length;
  const openIdx = data.indexOf(opening);
  const closeIdx = openIdx >= 0 ? data.indexOf(closing, openIdx) : -1;
  // Reject ambiguous multi-block input: a second opening marker after the
  // first close means the input contains more than one block.
  if (openIdx >= 0 && closeIdx >= 0) {
    const secondOpen = data.indexOf(opening, closeIdx + closing.length);
    if (secondOpen >= 0) {
      throw new Error(`multiple ${opening} blocks — refusing ambiguous input`);
    }
  }
  if (openIdx >= 0) start = openIdx + opening.length;
  if (closeIdx >= 0) end = closeIdx;
  return data.substring(start, end);
}
