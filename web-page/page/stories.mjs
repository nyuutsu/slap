// Wired once against the whole page rather than the stage alone, so any element marking itself data-story joins in.
// A story is a view-transient, never state: it floats over the voice box in a .story-card,
// because a story that grew the box would slide the page out from under the pointer that asked, and the leave-speak-leave loop would thrash.
// Leaving settles it — the voice box renders back to what the state says — except a control being typed in,
// whose story stays, because that render would tear focus out of the input.
// The .has-story buttons carry aria-expanded; a press speaks, Escape settles, and the card itself counts as staying.

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
    const departed = event.target.closest?.('[data-story], .story-card');
    if (!departed || !spokenStoried) return;
    if (event.relatedTarget?.closest?.('[data-story], .story-card')) return;
    if (spokenStoried.contains(document.activeElement)) return;
    quietStory(spokenStoried);
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
