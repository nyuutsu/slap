// Watches for a newer build of the page. The service worker precaches each deploy whole, so the page needs
// no server after load: visits are instant, offline works. A newer deploy installs beside the current one as
// a complete cache and, untaken, steps in only when every slap tab has closed — one visit late, never a mixed
// generation. The fellow offers a waiting build when his hands are empty, and "take it" asks it to step in
// now: one reload, rather than a wait for the last tab to close.

let waitingWorker = null;

export const newerPageWaiting = () => waitingWorker !== null;

// registration is pinned to the real host, so the rig and the node checks never meet it
export const watchForNewerPage = (whenNewerPageWaits) => {
  if (location.hostname !== 'slap.nyuu.page' || !navigator.serviceWorker) return;
  navigator.serviceWorker.register('/sw.js').then((registration) => {
    const noteAnyWaitingBuild = () => {
      // a worker installed with no controller yet is the first visit taking its seat, not a newer page
      if (!registration.waiting || !navigator.serviceWorker.controller) return;
      waitingWorker = registration.waiting;
      whenNewerPageWaits();
    };
    noteAnyWaitingBuild();                      // a build already waiting when this visit began
    registration.addEventListener('updatefound', () => {
      const arrivingWorker = registration.installing;
      arrivingWorker?.addEventListener('statechange', () => {
        if (arrivingWorker.state === 'installed') noteAnyWaitingBuild();
      });
    });
  }).catch(console.error);
};

export const takeTheNewerPage = () => {
  if (!waitingWorker) return;
  // the reload waits for the handover: reloading before the new worker holds the page would serve this build again
  navigator.serviceWorker.addEventListener('controllerchange', () => location.reload(), { once: true });
  waitingWorker.postMessage('take-the-newer-page');
};
