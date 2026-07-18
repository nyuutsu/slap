// The googly-eyed fellow beside the answer surface: the face of slap's voice.
// The bandage artwork lives in art/bandage.svg, its one home; the eyes are drawn on top here.
// Moods are named for what he does, not for what happened: the caller decides when a nod is due.

const eyesMarkup = `
  <g>
    <circle cx="72" cy="45" r="13" fill="#fff" stroke="#2f2f2f" stroke-width="2.4"/>
    <circle class="pupil" cx="72" cy="48" r="5.5" fill="#1a1a1a"/>
    <path class="smile-eye" d="M65 45 Q72 52 79 45" fill="none" stroke="#1a1a1a" stroke-width="3" stroke-linecap="round" opacity="0"/>
  </g>
  <g>
    <circle cx="55" cy="62" r="13" fill="#fff" stroke="#2f2f2f" stroke-width="2.4"/>
    <circle class="pupil" cx="55" cy="65" r="5.5" fill="#1a1a1a"/>
    <path class="smile-eye" d="M48 62 Q55 69 62 62" fill="none" stroke="#1a1a1a" stroke-width="3" stroke-linecap="round" opacity="0"/>
  </g>`;

const restingEyeCenters = [{ x: 72, y: 45 }, { x: 55, y: 62 }];

export const seatMascot = async (seat) => {
  seat.innerHTML = await (await fetch('art/bandage.svg')).text();
  const figure = seat.querySelector('svg');
  figure.removeAttribute('width');
  figure.removeAttribute('height');
  figure.innerHTML += eyesMarkup;

  const pupils = [...figure.querySelectorAll('.pupil')];
  const smileEyes = [...figure.querySelectorAll('.smile-eye')];
  const stillness = matchMedia('(prefers-reduced-motion: reduce)');

  // A small spring: the pupils glide toward their target, the body bobs and rights itself.
  let gazeX = 0, gazeY = 2, gazeVelocityX = 0, gazeVelocityY = 0, gazeTargetX = 0, gazeTargetY = 2;
  let bob = 0, bobVelocity = 0, tilt = 0, tiltVelocity = 0;
  let tracking = true, smiling = false;
  const clamped = (value) => Math.max(-6, Math.min(6, value));

  const springTick = () => {
    gazeVelocityX += (gazeTargetX - gazeX) * 0.09; gazeVelocityY += (gazeTargetY - gazeY) * 0.09;
    gazeVelocityX *= 0.86; gazeVelocityY *= 0.86;
    gazeX += gazeVelocityX; gazeY += gazeVelocityY;
    pupils.forEach((pupil, which) => {
      pupil.setAttribute('cx', restingEyeCenters[which].x + clamped(gazeX));
      pupil.setAttribute('cy', restingEyeCenters[which].y + clamped(gazeY));
    });
    bobVelocity += (0 - bob) * 0.18; bobVelocity *= 0.80; bob += bobVelocity;
    tiltVelocity += (0 - tilt) * 0.18; tiltVelocity *= 0.80; tilt += tiltVelocity;
    figure.style.transform = `translateY(${bob.toFixed(2)}px) rotate(${tilt.toFixed(2)}deg)`;
    requestAnimationFrame(springTick);
  };
  springTick();

  const settle = () => {
    smiling = false; tracking = true;
    gazeTargetX = 0; gazeTargetY = 2;
    smileEyes.forEach((eye) => eye.setAttribute('opacity', 0));
    pupils.forEach((pupil) => pupil.setAttribute('opacity', 1));
  };

  addEventListener('mousemove', (cursor) => {
    if (!tracking) return;
    const box = figure.getBoundingClientRect();
    gazeTargetX = clamped((cursor.clientX - (box.left + box.width / 2)) / 40);
    gazeTargetY = clamped((cursor.clientY - (box.top + box.height / 2)) / 40) + 2;
  });
  figure.addEventListener('click', () => { if (!smiling && !stillness.matches) bobVelocity = -7; });

  let fidgetTimer = null;

  return {
    // a quiet acknowledgment — something landed
    nod() {
      settle(); tracking = false; gazeTargetY = 5;
      setTimeout(() => { gazeTargetY = -2; }, 130);
      setTimeout(() => { gazeTargetY = 2; tracking = true; }, 300);
    },
    // a pleased little lean
    lean() {
      settle();
      if (stillness.matches) return;
      tiltVelocity = 5; gazeTargetX = 3; gazeTargetY = 1;
      setTimeout(() => { gazeTargetX = 0; gazeTargetY = 2; }, 420);
    },
    // smile-eyes, and they stay: the person is still looking at the thing that went right,
    // so the smile lasts until something new begins — a fresh file, another verb, "do another"
    smile() {
      smiling = true; tracking = false; gazeTargetX = 0; gazeTargetY = 2;
      pupils.forEach((pupil) => pupil.setAttribute('opacity', 0));
      smileEyes.forEach((eye) => eye.setAttribute('opacity', 1));
      if (!stillness.matches) bobVelocity = -6;
    },
    // look down and aside, a little sorry
    droop() {
      smiling = true; tracking = false;
      pupils.forEach((pupil) => pupil.setAttribute('opacity', 1));
      smileEyes.forEach((eye) => eye.setAttribute('opacity', 0));
      gazeTargetX = -4; gazeTargetY = 6;
      setTimeout(() => { if (smiling) settle(); }, 2600);
    },
    // restless while a job runs; settle() ends it
    beginFidgeting() {
      settle();
      if (stillness.matches || fidgetTimer) return;
      fidgetTimer = setInterval(() => {
        tiltVelocity += Math.random() > 0.5 ? 2.4 : -2.4;
        gazeTargetX = Math.random() > 0.5 ? 3 : -3;
      }, 900);
    },
    settle() {
      if (fidgetTimer) { clearInterval(fidgetTimer); fidgetTimer = null; }
      settle();
    },
  };
};
