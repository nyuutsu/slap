// The one home for what the page knows about constraint axes, under dialect-controls.mjs's doctrine:
// spellings are boundary vocabulary, labels are the page's words, and whether one applies is the surface's formatConstraints to say.

export const constraintControls = {
  SMCShapeConstraint: {
    controlLabel: "stay within SNESTool's limits",
    controlWhy: 'a very old dos patcher. you almost certainly don\'t need this',
    terminalFlag: '--require-smc-shaped-target-size',
    requestKey: 'requestedSMCShape',
    chosenRequirement: 'RequireSMCShapedTruncation',
    restingRequirement: 'AllowAnyTruncationShape',
  },
};

export const constraintLabel = (constraintName) => constraintControls[constraintName]?.controlLabel ?? constraintName;
