// The googly-eyed fellow beside the answer surface: the face of slap's voice.
// The bandage artwork lives in art/bandage.svg, its one home; the eyes are drawn on top here.
// Moods are named for what he does, not for what happened: the caller decides when a nod is due.
// Asked for stillness he holds still, and changes expression regardless — a smile and a downcast look are tone, not motion.

const eyesMarkup = `
  <g>
    <circle cx="72" cy="45" r="13" fill="#fff" stroke="#2f2f2f" stroke-width="2.4"/>
    <circle class="pupil" cx="72" cy="48" r="5.5" fill="#1a1a1a"/>
    <path class="smile-eye" d="M65 45 Q72 52 79 45" fill="none" stroke="#1a1a1a" stroke-width="3" stroke-linecap="round" opacity="0"/>
    <path class="reeling-eye" d="M70.5 45 a1.5 1.5 0 0 1 3 0 a3 3 0 0 1 -6 0 a4.5 4.5 0 0 1 9 0" fill="none" stroke="#1a1a1a" stroke-width="2" stroke-linecap="round" opacity="0"/>
  </g>
  <g>
    <circle cx="55" cy="62" r="13" fill="#fff" stroke="#2f2f2f" stroke-width="2.4"/>
    <circle class="pupil" cx="55" cy="65" r="5.5" fill="#1a1a1a"/>
    <path class="smile-eye" d="M48 62 Q55 69 62 62" fill="none" stroke="#1a1a1a" stroke-width="3" stroke-linecap="round" opacity="0"/>
    <path class="reeling-eye" d="M53.5 62 a1.5 1.5 0 0 1 3 0 a3 3 0 0 1 -6 0 a4.5 4.5 0 0 1 9 0" fill="none" stroke="#1a1a1a" stroke-width="2" stroke-linecap="round" opacity="0"/>
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
  const reelingEyes = [...figure.querySelectorAll('.reeling-eye')];
  const stillness = matchMedia('(prefers-reduced-motion: reduce)');
  const holdingStill = () => stillness.matches;

  // A small spring: the pupils glide toward their target, the body bobs and rights itself.
  let gazeX = 0, gazeY = 2, gazeVelocityX = 0, gazeVelocityY = 0, gazeTargetX = 0, gazeTargetY = 2;
  let bob = 0, bobVelocity = 0, tilt = 0, tiltVelocity = 0;
  // an expression he is holding outlasts the moment that raised it, and keeps his eyes off the cursor until it clears
  let tracking = true, expressionHeld = false, springing = false;
  const clamped = (value) => Math.max(-6, Math.min(6, value));

  const paintGaze = () => pupils.forEach((pupil, which) => {
    pupil.setAttribute('cx', restingEyeCenters[which].x + clamped(gazeX));
    pupil.setAttribute('cy', restingEyeCenters[which].y + clamped(gazeY));
  });

  // He has three pairs of eyes and wears one at a time.
  const eyesBecome = (shape) => {
    pupils.forEach((pupil) => pupil.setAttribute('opacity', shape === 'watching' ? 1 : 0));
    smileEyes.forEach((eye) => eye.setAttribute('opacity', shape === 'smiling' ? 1 : 0));
    reelingEyes.forEach((eye) => eye.setAttribute('opacity', shape === 'reeling' ? 1 : 0));
  };

  // Where the eyes are asked to look. The spring is what carries them there, so in its absence they are already there.
  const aimGaze = (towardX, towardY) => {
    gazeTargetX = towardX; gazeTargetY = towardY;
    if (!holdingStill()) return;
    gazeX = towardX; gazeY = towardY;
    paintGaze();
  };

  const springTick = () => {
    if (holdingStill()) { springing = false; figure.style.transform = ''; return; }
    gazeVelocityX += (gazeTargetX - gazeX) * 0.09; gazeVelocityY += (gazeTargetY - gazeY) * 0.09;
    gazeVelocityX *= 0.86; gazeVelocityY *= 0.86;
    gazeX += gazeVelocityX; gazeY += gazeVelocityY;
    paintGaze();
    bobVelocity += (0 - bob) * 0.18; bobVelocity *= 0.80; bob += bobVelocity;
    tiltVelocity += (0 - tilt) * 0.18; tiltVelocity *= 0.80; tilt += tiltVelocity;
    figure.style.transform = `translateY(${bob.toFixed(2)}px) rotate(${tilt.toFixed(2)}deg)`;
    requestAnimationFrame(springTick);
  };
  const beginSpringing = () => { if (springing || holdingStill()) return; springing = true; springTick(); };

  paintGaze();
  beginSpringing();
  // the setting can turn over under a page already open, and he answers it whichever way it turns
  stillness.addEventListener('change', () => (holdingStill() ? aimGaze(0, 2) : beginSpringing()));

  const settle = () => {
    expressionHeld = false; tracking = true;
    aimGaze(0, 2);
    eyesBecome('watching');
  };

  addEventListener('mousemove', (cursor) => {
    if (!tracking || holdingStill()) return;
    const box = figure.getBoundingClientRect();
    gazeTargetX = clamped((cursor.clientX - (box.left + box.width / 2)) / 40);
    gazeTargetY = clamped((cursor.clientY - (box.top + box.height / 2)) / 40) + 2;
  });
  figure.addEventListener('click', () => { if (!expressionHeld && !holdingStill()) bobVelocity = -7; });

  let fidgetTimer = null;

  return {
    // a quiet acknowledgment — something landed
    nod() {
      settle();
      if (holdingStill()) return;
      tracking = false; gazeTargetY = 5;
      setTimeout(() => { gazeTargetY = -2; }, 130);
      setTimeout(() => { gazeTargetY = 2; tracking = true; }, 300);
    },
    // a pleased little lean
    lean() {
      settle();
      if (holdingStill()) return;
      tiltVelocity = 5; gazeTargetX = 3; gazeTargetY = 1;
      setTimeout(() => { gazeTargetX = 0; gazeTargetY = 2; }, 420);
    },
    // smile-eyes, and they stay: the person is still looking at the thing that went right,
    // so the smile lasts until something new begins — a fresh file, another verb, "do another"
    smile() {
      expressionHeld = true; tracking = false; aimGaze(0, 2);
      eyesBecome('smiling');
      if (!holdingStill()) bobVelocity = -6;
    },
    // look down and aside, a little sorry
    droop() {
      expressionHeld = true; tracking = false;
      eyesBecome('watching');
      aimGaze(-4, 6);
      setTimeout(() => { if (expressionHeld) settle(); }, 2600);
    },
    // eyes gone to spirals: he is on screen but not working, and nothing on such a page will clear it
    reel() {
      expressionHeld = true; tracking = false;
      eyesBecome('reeling');
    },
    // restless while a job runs; settle() ends it
    beginFidgeting() {
      settle();
      if (holdingStill() || fidgetTimer) return;
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
