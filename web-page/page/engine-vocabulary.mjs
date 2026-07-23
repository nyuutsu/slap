// The one home for the wire sums the page dispatches on, and the mechanism that keeps the dispatch honest.
// Each table answers only the names it was built with: a misspelled tag throws at the reference,
// instead of riding downstream as an always-false comparison. matcherOver checks its arms against the
// table while the module loads, so a missing or misspelled arm fails the boot check, never a person.

const sumName = Symbol('the sum’s name');
const wireSumName = Symbol('the wire sum’s own name, as the engine speaks it');
const sumEntries = Symbol('the sum’s entries, spoken name → wire tag');

// JS probes objects on its own — a promise resolution asks for `then`, JSON.stringify for `toJSON`,
// the console for inspection hooks — and those probes are nowhere near a typo, so they pass through.
const runtimeProbes = new Set(['then', 'toJSON', 'constructor', 'inspect']);

const allVocabularies = [];

const vocabulary = (name, spokenBy, entries) => {
  const table = new Proxy(
    Object.freeze({ ...entries, [sumName]: name, [wireSumName]: spokenBy, [sumEntries]: Object.freeze({ ...entries }) }),
    {
      get(inner, key) {
        if (typeof key === 'symbol' || runtimeProbes.has(key) || key in inner) return inner[key];
        throw new Error(`${name} has no constructor spelled ${key}`);
      },
    });
  allVocabularies.push(table);
  return table;
};

// Every table, by construction — the census audits each one against the engine's own vocabulary.
export const spokenVocabularies = allVocabularies;

export const wireSumNameOf = (table) => table[wireSumName];

// The verification verdict (Slap.Verify): what weighing a rom against a patch's declarations said.
export const Verdict = vocabulary('Verdict', 'VerificationVerdict', {
  Matches:     'VerdictMatches',
  Differs:     'VerdictDiffers',
  Uncheckable: 'VerdictUncheckable',
});

// Whether a run's verdicts describe the files as handed (Slap.Apply).
export const Standing = vocabulary('Standing', 'VerdictStanding', {
  DescribeTheFiles:  'VerdictsDescribeTheFiles',
  WithheldReshaped:  'VerdictsWithheldReshaped',
});

// An emit check's answer (Slap.Web.Envelope): would this create or convert be correct as declared?
export const CheckVerdict = vocabulary('CheckVerdict', 'SpokenVerdict', {
  Ready:   'SpokenReady',
  Blocked: 'SpokenBlocked',
});

// Whether a patch can be taken back off (Slap.SomePatch).
export const UndoAnswer = vocabulary('UndoAnswer', 'UndoAnswer', {
  PatchIsItsOwnReverse:  'PatchIsItsOwnReverse',
  PatchCarriesUndoData:  'PatchCarriesUndoData',
  AuthorOmittedUndoData: 'AuthorOmittedUndoData',
  FormatHasNoUndo:       'FormatHasNoUndo',
});

// What an analysis region does to the bytes (Slap.Display.Analysis), and where a copy reads from.
export const Payload = vocabulary('Payload', 'AnalysisPayload', {
  Write: 'PayloadWrite',
  Fill:  'PayloadFill',
  Copy:  'PayloadCopy',
  XOR:   'PayloadXOR',
  Meta:  'PayloadMeta',
});

export const CopySource = vocabulary('CopySource', 'CopySource', {
  FromSource: 'FromSource',
  FromTarget: 'FromTarget',
  FromPatch:  'FromPatch',
});

// What a VCDIFF arc does when no window size is requested (Slap.Web).
export const WindowDefault = vocabulary('WindowDefault', 'WindowDefault', {
  WindowsOfBytes:      'WindowsOfBytes',
  OneWindowWholeTarget: 'OneWindowWholeTarget',
});

// The control a metadata field wants (Slap.Surface).
export const ControlKind = vocabulary('ControlKind', 'MetadataFieldKind', {
  FreeText: 'FreeTextField',
  Number:   'NumberField',
  Toggle:   'ToggleField',
  Choice:   'ChoiceField',
  File:     'FileField',
});

// Which seat a dropped file belongs in (Slap.Detect).
export const Sorting = vocabulary('Sorting', 'DroppedFileAnswer', {
  AsPatch: 'SortsAsPatch',
  AsRom:   'SortsAsRom',
});

// An analysis's sections (Slap.Display.Analysis): the regions, and the prose around them.
export const Section = vocabulary('Section', 'AnalysisSection', {
  Regions: 'SectionRegions',
  Labeled: 'SectionLabeled',
  Text:    'SectionText',
});

// A tally's byte count (Slap.Display.Common): a declared output size, or payload bytes summed.
export const ByteCount = vocabulary('ByteCount', 'ByteCount', {
  TotalOutput:  'TotalOutputBytes',
  TotalPayload: 'TotalPayloadBytes',
});

// Whether an analysis carries a summary (Slap.Display.Analysis).
export const Summarized = vocabulary('Summarized', 'AnalysisSummary', {
  Summary: 'Summary',
  None:    'SummaryNone',
});

// A patch's embedded text or blob fields (Slap.Display.EmbeddedContent).
export const EmbeddedField = vocabulary('EmbeddedField', 'EmbeddedField', {
  Absent:  'FieldAbsent',
  Empty:   'FieldEmpty',
  Content: 'FieldContent',
});

// A region annotation's details (Slap.Display.Analysis).
export const Detail = vocabulary('Detail', 'AnnotDetail', {
  RLE:              'DetailRLE',
  Undo:             'DetailUndo',
  Delta:            'DetailDelta',
  Skip:             'DetailSkip',
  Add:              'DetailAdd',
  Copy:             'DetailCopy',
  Seek:             'DetailSeek',
  Source:           'DetailSource',
  SourceIndex:      'DetailSourceIndex',
  CRC16:            'DetailCRC16',
  CursorUnderflow:  'DetailCursorUnderflow',
});

export const spokenTagsOf = (table) => Object.values(table[sumEntries]);

// A total case expression over one sum. Arms are keyed by the table's spoken names and receive
// (contents, context, whole); the matched value may be a tagged record or the bare tag string.
export const matcherOver = (table, arms) => {
  const name = table[sumName];
  const entries = table[sumEntries];
  for (const spokenName of Object.keys(entries))
    if (!(spokenName in arms)) throw new Error(`a matcher over ${name} is missing its ${spokenName} arm`);
  const armByWireTag = {};
  for (const [spokenName, arm] of Object.entries(arms)) {
    if (!(spokenName in entries)) throw new Error(`a matcher over ${name} has an arm ${spokenName} the sum does not`);
    armByWireTag[entries[spokenName]] = arm;
  }
  return (value, context) => {
    const wireTag = typeof value === 'string' ? value : value.tag;
    const arm = armByWireTag[wireTag];
    if (!arm) throw new Error(`the engine spoke a ${name} the page does not know: ${wireTag}`);
    return arm(typeof value === 'string' ? value : value.contents, context, value);
  };
};
