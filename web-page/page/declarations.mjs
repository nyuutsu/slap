// The JSON halves of the reactor requests spoken by more than one verb.
// A verb's own declaration lives with the verb, so only the genuinely shared shapes sit here.

export const identifyDeclaration = (patchOrigin, metadataEncoding) => ({
  declaredIdentifyDialects: { requestedPatchOrigin: patchOrigin },
  declaredIdentifyMetadataEncoding: metadataEncoding,
});
