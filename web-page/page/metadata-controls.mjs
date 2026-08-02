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
  MetadataStability:             { label: 'mark unstable', why: 'a work in progress; it applies just the same either way' },
  MetadataRomType:               { label: 'rom type' },
  MetadataImageType:             { label: 'image type' },
  MetadataFileIdDiz:             { label: 'FILE_ID.DIZ' },
  MetadataGenre:                 { label: 'genre' },
  MetadataLanguage:              { label: 'language' },
  MetadataDate:                  { label: 'date' },
  MetadataWebsite:               { label: 'website' },
  MetadataTextMode:              { label: 'text mode' },
  MetadataEmbeddedBlob:          { label: 'embedded data' },
  MetadataXDelta1FromName:       { label: 'source name', why: "recorded in the patch; defaults to the file's own" },
  MetadataXDelta1ToName:         { label: 'target name', why: "recorded in the patch; defaults to the file's own" },
  MetadataWindowSize:            { label: 'window size' },
};

export const fieldLabel = (fieldName, fallbackWord) => fieldWords[fieldName]?.label ?? fallbackWord ?? fieldName;
export const fieldWhy = (fieldName) => fieldWords[fieldName]?.why ?? null;

// A gloss describes the chosen token; at rest, a crossed default speaks for itself.
// Only some choices carry words — a token that says enough for itself stays bare. (All of this copy: DRAFT.)
const choiceWords = {
  MetadataSecondaryCompressor: {
    tokens: {
      lzma: 'the same compression xz uses, and squeezes hardest of the three.',
      djw:  "xdelta3's own. it doesn't squeeze as hard.",
      fgk:  "xdelta3's own, and its source calls it a demonstration.",
    },
  },
  MetadataImageType: {
    tokens: {
      bin: 'the right answer for everything except a primodvd image.',
      gi:  'a primodvd image, which puts the checked bytes somewhere else.',
    },
  },
  MetadataTextMode: {
    tokens: {
      utf8:       'says the text is UTF-8, which it is.',
      undeclared: "same bytes; the patch just won't say so.",
    },
  },
};

export const choiceGloss = (fieldName, chosenToken) =>
  chosenToken ? choiceWords[fieldName]?.tokens[chosenToken] ?? null : null;

// Both name fields are the same story told from either end.
const xdelta1NameStory =
  'xdelta1 keeps the names of the two files a patch was made from. '
  + "the classic tool falls back to them when you don't name files yourself, "
  + 'opening the from-name and writing the to-name. '
  + 'i always have both names already, so i just record these and show them back to you.';

// The longer stories the fellow tells when a control is hovered or focused.
export const fieldStories = {
  MetadataWindowSize:
    'a vcdiff patch is written in windows. each one is a self-contained slice of the output. '
    + 'smaller windows are kinder to weaker decoders, bigger ones squeeze a little more. '
    + "empty means the format's own default, and that's a fine place to leave it.",
  MetadataSecondaryCompressor:
    "each window's sections can take a second layer of packing inside the patch. "
    + 'this picks the algorithm. skip compression turns the layer off altogether.',
  MetadataImageType:
    'ppf3 checks its patch against a sample of the original, and different kinds of disc image '
    + 'lay that sample out differently. this says which kind the original is. '
    + "if you're not sure, bin is the usual answer and already the default.",
  MetadataEmbeddedBlob:
    'the patch can carry a free-form note inside itself. '
    + "type one and i'll dress it the way the format wants. "
    + 'hand me a file instead and the bytes go in exactly as they are.',
  MetadataFileIdDiz:
    'file_id.diz is an old bulletin board thing, a little description file. '
    + 'this one rides inside the patch, and ppf tools show it to anyone who asks the patch about itself.',
  MetadataTextMode:
    "when one of these turns up, i can't work out the encoding from the patch, so i ask which one to use.",
  MetadataXDelta1FromName: xdelta1NameStory,
  MetadataXDelta1ToName: xdelta1NameStory,
};
