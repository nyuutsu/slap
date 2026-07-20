// Wired once against the whole page rather than the stage alone, so any element marking itself data-story joins in.
// A story is a view-transient, never state: leaving renders the voice box back to what the state says,
// and a control being typed in keeps its story, because that render would tear focus out of the input.

import { plainVoice } from './answer-surface.mjs';

export const wireStoryListeners = (host, storybook, storiesQuietNow) => {
  const speakStory = (event) => {
    if (storiesQuietNow()) return;
    const storied = event.target.closest('[data-story]');
    const story = storied && storybook[storied.dataset.story];
    if (!story) return;
    host.fellow.lean();
    host.murmur(plainVoice(story));
  };
  const settleStory = (event) => {
    const storied = event.target.closest?.('[data-story]');
    if (!storied) return;
    if (event.relatedTarget && storied.contains(event.relatedTarget)) return;
    if (storied.contains(document.activeElement)) return;
    host.fellow.settle();
    host.render();
  };
  document.addEventListener('mouseover', speakStory);
  document.addEventListener('focusin', speakStory);
  document.addEventListener('mouseout', settleStory);
  document.addEventListener('focusout', settleStory);
};
