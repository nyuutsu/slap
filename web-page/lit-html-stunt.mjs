// The node checks' stunt double for lit-html: the same template calls, rendered eagerly to strings.
// The point is the throwing. lit quietly renders a bare `false` as the text "false" and ignores a value standing
// alone inside a tag — the two shapes a `cond && …` takes when it should have been `cond ? … : nothing` or a
// `?attribute=` binding — so the stunt makes both loud. Deltas from lit, harmless to a string comparison:
// a property binding renders as an attribute, and `nothing` inside a quoted attribute leaves it empty rather than absent.

const escapeText = (value) => String(value)
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

// lit's own registered symbol, so the sentinel survives comparison whichever module supplied it.
export const nothing = Symbol.for('lit-nothing');

const stuntMarkup = Symbol('stunt markup');

const attributeBindingAtTail = /([.?@]?)([A-Za-z][\w-]*)=$/;

const childMarkup = (value) => {
  if (value === null || value === undefined || value === nothing || value === '') return '';
  if (Array.isArray(value)) return value.map(childMarkup).join('');
  if (typeof value === 'object' && stuntMarkup in value) return value[stuntMarkup];
  if (typeof value === 'boolean') throw new Error('a boolean reached child position — lit would print it; write `cond ? markup : nothing`');
  if (typeof value === 'string' || typeof value === 'number') return escapeText(value);
  throw new Error(`a ${typeof value} reached child position`);
};

// The scanner knows just enough HTML to say where each seam sits: text, inside a tag, or inside a quoted attribute.
export const html = (parts, ...values) => {
  let built = '';
  let state = 'text';
  parts.forEach((part, partIndex) => {
    for (const character of part) {
      if (state === 'text') { if (character === '<') state = 'tag'; }
      else if (state === 'tag') {
        if (character === '"') state = 'double-quoted';
        else if (character === "'") state = 'single-quoted';
        else if (character === '>') state = 'text';
      }
      else if (state === 'double-quoted') { if (character === '"') state = 'tag'; }
      else if (state === 'single-quoted') { if (character === "'") state = 'tag'; }
    }
    built += part;
    if (partIndex === parts.length - 1) return;
    const value = values[partIndex];
    if (state === 'text') {
      built += childMarkup(value);
    } else if (state === 'double-quoted' || state === 'single-quoted') {
      built += value === nothing || value === null || value === undefined ? '' : escapeText(value);
    } else {
      const binding = built.match(attributeBindingAtTail);
      if (!binding) throw new Error('a value stands bare inside a tag — lit accepts only directives there; a conditional attribute wants `?attribute=` or `attribute=${cond ? word : nothing}`');
      const [bindingText, sigil, attributeName] = binding;
      built = built.slice(0, -bindingText.length);
      if (sigil === '@') throw new Error(`the stunt does not speak event bindings (@${attributeName})`);
      if (sigil === '?' || typeof value === 'boolean') built += value && value !== nothing ? `${attributeName}=""` : '';
      else if (value === nothing || value === null || value === undefined) built += '';
      else built += `${attributeName}="${escapeText(value)}"`;
    }
  });
  return { [stuntMarkup]: built };
};

export const markupOf = (rendered) => {
  if (rendered === null || typeof rendered !== 'object' || !(stuntMarkup in rendered))
    throw new Error('not a rendered template');
  return rendered[stuntMarkup];
};

export const render = (rendered, container) => { container.innerHTML = markupOf(rendered); };
