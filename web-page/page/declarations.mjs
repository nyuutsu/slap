// The JSON halves of the reactor requests spoken by more than one verb.
// A verb's own declaration lives with the verb, so only the genuinely shared shapes sit here.

export const identifyDeclaration = (ppf1Origin, metadataEncoding) => ({
  declaredIdentifyDialects: { requestedPPF1Origin: ppf1Origin },
  declaredIdentifyMetadataEncoding: metadataEncoding,
});
