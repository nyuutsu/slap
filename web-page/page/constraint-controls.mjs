// The one home for what the page knows about constraint axes, under dialect-controls.mjs's doctrine:
// spellings are boundary vocabulary, labels are the page's words, and whether one applies is the surface's formatConstraints to say.

export const constraintControls = {
  SMCShapeConstraint: {
    controlLabel: 'require SMC-shaped size',
    controlWhy: 'refuse a truncation marker at a size SNESTool would not accept',
    terminalFlag: '--require-smc-shaped-target-size',
    requestKey: 'requestedSMCShape',
    chosenRequirement: 'RequireSMCShapedTruncation',
    restingRequirement: 'AllowAnyTruncationShape',
  },
};

export const constraintLabel = (constraintName) => constraintControls[constraintName]?.controlLabel ?? constraintName;
