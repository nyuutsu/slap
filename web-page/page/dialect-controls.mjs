// The one home for what the page knows about dialect axes.
// An axis's name and its request spelling are boundary vocabulary, the same category as a declaration's field names;
// when an axis applies is never the page's to know: the identity's applicableDialects says so per patch.
// An axis with no row here gets no control: quiet, never wrong. A new row is authored opinion, the page's to write.

import { toggleMarkup } from './controls.mjs';

export const dialectControls = {
  PPF1OriginAxis: {
    controlLabel: 'Amiga byte order',
    controlWhy: 'this PPF1 reads its offsets big-endian',
    terminalFlag: '--is-amiga-patch',
    chosenOrigin: 'PPF1OriginAmiga',
    restingOrigin: 'PPF1OriginPC',
  },
};

// Only one verb's stage is mounted at a time, so the ids stay unique unqualified.
export const dialectTogglesMarkup = (applicableAxes, currentOrigin) =>
  applicableAxes.flatMap((axis) => {
    const control = dialectControls[axis];
    if (!control) return [];
    return [toggleMarkup({
      id: `dialect-${axis}`,
      setting: 'dialect',
      checked: currentOrigin === control.chosenOrigin,
      label: control.controlLabel,
      why: control.controlWhy,
    })];
  });
