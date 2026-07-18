// Small renderers for values the engine hands across:
// counts read decimal, positions and checksums read hex, and byte hashes arrive base64.

export const humanByteSize = (byteCount) =>
  byteCount < 1024 ? `${byteCount} B`
  : byteCount < 1048576 ? `${(byteCount / 1024).toFixed(1)} KB`
  : byteCount < 1073741824 ? `${(byteCount / 1048576).toFixed(2)} MB`
  : `${(byteCount / 1073741824).toFixed(2)} GB`;

export const groupedCount = (count) => count.toLocaleString('en-US');

export const crc32Hex = (crcValue) => (crcValue >>> 0).toString(16).padStart(8, '0');

export const base64ToHex = (base64Bytes) =>
  [...atob(base64Bytes)].map((byte) => byte.charCodeAt(0).toString(16).padStart(2, '0')).join('');

// "size", "size and CRC32", "size, CRC32 and MD5"
export const proseList = (words) =>
  words.length <= 1 ? (words[0] ?? '')
  : `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;

// The engine speaks DeclaredCheckKind constructor names; the page says them with the same
// nouns the CLI's report uses (declaredCheckKindNoun, Slap.Status.Vocabulary).
const checkKindNouns = {
  DeclaredCRC32: 'CRC',
  DeclaredMD5: 'MD5',
  DeclaredSHA1: 'SHA1',
  DeclaredFileSize: 'declared size',
  DeclaredBlockCRC16: 'block CRC16s',
  DeclaredValidationBlock: 'validation block',
  DeclaredByteComparison: 'identifying bytes',
  DeclaredByteOrder: 'byte order',
  DeclaredWindowAdler32: 'window checksums',
};
export const checkKindNoun = (kindName) => checkKindNouns[kindName] ?? kindName;

// A FormatLabel constructor name worn plainly — the stand-in while the identity's own
// spoken name ('spokenIdentityFormatName') hasn't answered yet.
export const formatLabelWord = (labelName) => labelName.replace(/^Label/, '');
