// The one home for what the page knows about metadata fields.
// A field's request spellings — its declaration key, a toggle's requested value, the typed-text flags —
// are boundary vocabulary, the same category as a declaration's field names; the labels are the page's own words.
// Which fields a format accepts, and how each is set, is never the page's to know:
// the surface's formatAcceptedFields and the field roster's control kinds say so.

export const requestKeyOf = (fieldName) => 'requested' + fieldName.slice('Metadata'.length);

// create writes every text field as UTF-8, exactly as the CLI does.
export const utf8Text = (content) => ({ encodedTextEncoding: 'utf-8', encodedTextContent: content });

// Checked asks for the named value; unchecked requests nothing and the format keeps its default.
// A toggle field with no spelling here gets no control: quiet, never wrong.
export const toggleRequests = {
  MetadataUndoInclusion:         'OmitUndoData',
  MetadataVerificationInclusion: 'OmitVerification',
  MetadataPatchCompression:      'OmitCompression',
  MetadataStability:             'UnstablePatch',
};

// The blob and the DIZ ride lanes of their own; the file lane's flag rides the roster, the typed and drop lanes' flags are spelled here.
export const typedTextFlags = {
  MetadataEmbeddedBlob: '--metadata-text',
  MetadataFileIdDiz:    '--diz-text',
};

export const dropFlags = {
  MetadataEmbeddedBlob: '--drop-metadata',
  MetadataFileIdDiz:    '--drop-diz',
};

// The engine's own labels for carried content (an inspect's infoEmbedded rows), joined to the field whose convert intent governs them.
export const carriedFieldLabels = {
  'file_id.diz':   'MetadataFileIdDiz',
  'embedded data': 'MetadataEmbeddedBlob',
  'app header':    'MetadataEmbeddedBlob',
};

// The CLI's own @--window-size@ suffixes, so the tutor prints the very value the person typed.
export const windowUnits = [
  { token: 'bytes', suffix: '',  bytesPer: 1 },
  { token: 'KiB',   suffix: 'k', bytesPer: 1024 },
  { token: 'MiB',   suffix: 'm', bytesPer: 1024 * 1024 },
];

// A choice field the toggle conceals: with the toggle on, the choice would do nothing,
// so the control steps aside and its selection stays out of the declaration.
// A DOM-hacked pair still meets the engine's own refusal.
export const concealedWhileToggled = {
  MetadataSecondaryCompressor: 'MetadataPatchCompression',
};

const fieldWords = {
  MetadataTitle:                 { label: 'title' },
  MetadataAuthor:                { label: 'author' },
  MetadataDescription:           { label: 'description' },
  MetadataVersion:               { label: 'version' },
  MetadataUndoInclusion:         { label: 'omit undo data', why: "smaller patch; it can't be peeled back off" },
  MetadataVerificationInclusion: { label: 'omit verification', why: 'no checks for whoever applies it' },
  MetadataPatchCompression:      { label: 'skip compression', why: 'bigger patch, plainer bytes' },
  MetadataSecondaryCompressor:   { label: 'compress with' },
  MetadataStability:             { label: 'mark unstable', why: 'flags the patch as a work in progress' },
  MetadataRomType:               { label: 'rom type' },
  MetadataImageType:             { label: 'image type' },
  MetadataFileIdDiz:             { label: 'FILE_ID.DIZ' },
  MetadataGenre:                 { label: 'genre' },
  MetadataLanguage:              { label: 'language' },
  MetadataDate:                  { label: 'date' },
  MetadataWebsite:               { label: 'website' },
  MetadataTextMode:              { label: 'text mode' },
  MetadataEmbeddedBlob:          { label: 'embedded metadata' },
  MetadataXDelta1FromName:       { label: 'source name', why: "recorded in the patch; defaults to the file's own" },
  MetadataXDelta1ToName:         { label: 'target name', why: "recorded in the patch; defaults to the file's own" },
  MetadataWindowSize:            { label: 'window size', why: 'empty means the format decides' },
};

export const fieldLabel = (fieldName, fallbackWord) => fieldWords[fieldName]?.label ?? fallbackWord ?? fieldName;
export const fieldWhy = (fieldName) => fieldWords[fieldName]?.why ?? null;

// A gloss describes the chosen token; at rest, a crossed default speaks for itself.
// Only some choices carry words — a token that says enough for itself stays bare. (All of this copy: DRAFT.)
const choiceWords = {
  MetadataSecondaryCompressor: {
    tokens: {
      lzma: "xz-style LZMA2 — the canonical tool's own pick.",
      djw:  "xdelta3's own static Huffman coder.",
      fgk:  "adaptive Huffman — xdelta3's demonstration codec.",
    },
  },
  MetadataImageType: {
    tokens: {
      bin: 'a raw .bin disc image, 2352-byte sectors.',
      gi:  'a Global Image (.gi) dump.',
    },
  },
  MetadataTextMode: {
    tokens: {
      utf8:       'declares the texts as UTF-8.',
      undeclared: 'leaves the encoding unstated, as older patches did.',
    },
  },
};

export const choiceGloss = (fieldName, chosenToken, defaultToken) => {
  if (chosenToken) return choiceWords[fieldName]?.tokens[chosenToken] ?? null;
  return defaultToken ? `${defaultToken} unless you say otherwise.` : null;
};

// The longer stories the fellow tells when a control is hovered or focused. (All DRAFT.)
export const fieldStories = {
  MetadataWindowSize:
    'a VCDIFF patch is written in windows, each one a self-contained slice of the output. '
    + 'smaller windows help weaker decoders; bigger ones compress a little better. '
    + "empty means the format's own default, and that's a fine place to leave it.",
  MetadataSecondaryCompressor:
    "inside the patch, each window's sections can take a second layer of packing. "
    + 'this picks the algorithm; skip compression switches the layer off entirely.',
  MetadataImageType:
    'PPF3 checks the patch against a sample of the disc image, and .bin and .gi images '
    + 'lay that sample out differently — this says which kind yours is.',
  MetadataEmbeddedBlob:
    "a free-form note carried inside the patch itself. type it and slap wraps it properly; "
    + 'hand over a file and the bytes go in exactly as they are.',
  MetadataFileIdDiz:
    'the old bulletin-board description file, carried inside the patch. '
    + 'PPF tools show it when someone inspects the patch.',
};
