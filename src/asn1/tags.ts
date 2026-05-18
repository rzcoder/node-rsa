export const Tag = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OBJECT_IDENTIFIER: 0x06,
  SEQUENCE: 0x30,
} as const;

export function tagName(tag: number): string {
  switch (tag) {
    case Tag.INTEGER:
      return 'INTEGER';
    case Tag.BIT_STRING:
      return 'BIT STRING';
    case Tag.OCTET_STRING:
      return 'OCTET STRING';
    case Tag.NULL:
      return 'NULL';
    case Tag.OBJECT_IDENTIFIER:
      return 'OBJECT IDENTIFIER';
    case Tag.SEQUENCE:
      return 'SEQUENCE';
    default:
      return `tag 0x${tag.toString(16).padStart(2, '0')}`;
  }
}
