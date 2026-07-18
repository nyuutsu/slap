// Literal parts are the author's own; every interpolation is escaped text, so a filename can never become markup.

export const escapeText = (value) => String(value)
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

const trustedMarkup = Symbol('trusted markup');

const raw = (markup) => ({ [trustedMarkup]: markup });

const renderedSeam = (seam) => {
  if (seam === null || seam === undefined || seam === false) return '';
  if (Array.isArray(seam)) return seam.map(renderedSeam).join('');
  if (typeof seam === 'object' && trustedMarkup in seam) return seam[trustedMarkup];
  return escapeText(seam);
};

export const html = (parts, ...seams) => raw(
  parts.slice(1).reduce((built, part, seamIndex) => built + renderedSeam(seams[seamIndex]) + part, parts[0])
);

export const markupOf = (built) => built[trustedMarkup];
