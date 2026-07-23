// Wired once against the whole page rather than the stage alone, so any element marking itself data-story joins in.
// A story is a view-transient, never state: leaving renders the voice box back to what the state says,
// and a control being typed in keeps its story, because that render would tear focus out of the input.
// The .has-story buttons carry aria-expanded, saying whether their story is the one being spoken;
// a press speaks it, Escape or leaving settles it.

import { plainVoice } from './answer-surface.mjs';

export const wireStoryListeners = (host, storybook, storiesQuietNow) => {
  let spokenStoried = null;

  const markExpanded = (storied, expanded) => {
    if (storied.classList?.contains('has-story')) storied.setAttribute('aria-expanded', String(expanded));
  };

  const speakStory = (event) => {
    if (storiesQuietNow()) return;
    const storied = event.target.closest('[data-story]');
    const story = storied && storybook[storied.dataset.story];
    if (!story) return;
    if (spokenStoried && spokenStoried !== storied) markExpanded(spokenStoried, false);
    markExpanded(storied, true);
    spokenStoried = storied;
    host.fellow.lean();
    host.murmur(plainVoice(story));
  };

  const quietStory = (storied) => {
    markExpanded(storied, false);
    if (spokenStoried === storied) spokenStoried = null;
    host.fellow.settle();
    host.render();
  };

  const settleStory = (event) => {
    const storied = event.target.closest?.('[data-story]');
    if (!storied) return;
    if (event.relatedTarget && storied.contains(event.relatedTarget)) return;
    if (storied.contains(document.activeElement)) return;
    quietStory(storied);
  };

  document.addEventListener('mouseover', speakStory);
  document.addEventListener('focusin', speakStory);
  document.addEventListener('click', speakStory);
  document.addEventListener('mouseout', settleStory);
  document.addEventListener('focusout', settleStory);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && spokenStoried) quietStory(spokenStoried);
  });
};
