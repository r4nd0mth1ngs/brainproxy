// Runs in every document of the browser a login is recorded in. It reports what the person
// does (fields filled, buttons and links clicked, Enter pressed) through the __bpRecord
// binding, with a selector that finds the element again when the login is replayed.
(() => {
  if (window.__bpRecording) return;
  window.__bpRecording = true;
  const top = window.top === window;
  const send = (e) => {
    try {
      window.__bpRecord(JSON.stringify({ ...e, url: location.href, top, ts: Date.now() }));
    } catch (_) {}
  };
  // Only what the person does: an event a page script makes up would be made up again when
  // the steps are replayed. (__bpRecordAll is set for automated tests of a login page.)
  const trusted = (ev) => ev.isTrusted || window.__bpRecordAll === true;
  const target = (ev) => {
    const el = ev.composedPath ? ev.composedPath()[0] : ev.target;
    return el && el.nodeType === 1 ? el : null;
  };

  // A field text is typed into.
  const typed = (el) =>
    el.localName === 'textarea' ||
    (el.localName === 'input' &&
      !['checkbox', 'radio', 'submit', 'button', 'image', 'file', 'reset', 'hidden', 'range', 'color'].includes(el.type));
  const quote = (v) => '"' + String(v).replace(/["\\]/g, '\\$&').replace(/\n/g, '\\a ') + '"';
  const unique = (sel) => {
    try {
      return document.querySelectorAll(sel).length === 1;
    } catch (_) {
      return false;
    }
  };
  // Ids a framework makes up change from one page load to the next.
  const stable = (id) => !!id && id.length <= 64 && !/\d{4,}|[0-9a-f]{8,}|^[:\d]|^(ember|react|radix|headlessui|mui|input)-?\d/i.test(id);
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const label = (el) =>
    (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('alt') || '')
      .trim()
      .replace(/\s+/g, ' ')
      .slice(0, 80);
  const path = (el) => {
    const parts = [];
    for (let n = el; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
      if (stable(n.id) && unique('#' + CSS.escape(n.id))) {
        parts.unshift('#' + CSS.escape(n.id));
        break;
      }
      let part = n.localName;
      const same = n.parentElement ? [...n.parentElement.children].filter((c) => c.localName === n.localName) : [];
      if (same.length > 1) part += `:nth-of-type(${same.indexOf(n) + 1})`;
      parts.unshift(part);
    }
    return parts.join(' > ');
  };
  const selector = (el) => {
    const tag = el.localName;
    if (stable(el.id) && unique('#' + CSS.escape(el.id))) return { css: '#' + CSS.escape(el.id) };
    for (const a of ['data-testid', 'data-test', 'data-qa', 'data-cy', 'name', 'aria-label', 'placeholder', 'autocomplete']) {
      const v = el.getAttribute(a);
      if (!v || v.length > 80) continue;
      let css = `${tag}[${a}=${quote(v)}]`;
      if (unique(css)) return { css };
      // Radio buttons and a form's several submit buttons share a name.
      const value = el.getAttribute('value');
      if (value && value.length <= 80 && unique((css += `[value=${quote(value)}]`))) return { css };
    }
    const type = el.getAttribute('type');
    if (tag === 'input' && type && unique(`input[type=${quote(type)}]`)) return { css: `input[type=${quote(type)}]` };
    // A button or link, by what it says. Never a field that is typed in: what it "says" is
    // what was typed, the password included.
    const says = !typed(el) && tag !== 'textarea' && tag !== 'select';
    const text = says ? label(el) : '';
    const role = el.getAttribute('role');
    if (text && (role || ['button', 'a', 'summary', 'input'].includes(tag))) {
      const css = role ? `${tag}[role=${quote(role)}]` : tag;
      const same = [...document.querySelectorAll(css)].filter((c) => visible(c) && label(c) === text);
      if (same.length === 1) return { css, text };
    }
    return { css: path(el) };
  };

  const field = (el) => ({
    tag: el.localName,
    type: (el.getAttribute('type') || (el.localName === 'input' ? 'text' : '')).toLowerCase(),
    name: el.getAttribute('name') || '',
    id: el.id || '',
    autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
    maxlength: el.maxLength > 0 ? el.maxLength : 0,
    hint: (el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').slice(0, 80),
  });
  const ticked = (el) => el.localName === 'input' && (el.type === 'checkbox' || el.type === 'radio');

  // Text typed and not reported yet, and what was reported last for each field.
  const pending = new Map();
  const reported = new WeakMap();
  const report = (el) => {
    if (!pending.has(el)) return;
    const value = pending.get(el);
    pending.delete(el);
    if (reported.get(el) === value) return;
    reported.set(el, value);
    send({ t: 'fill', ...selector(el), ...field(el), value: String(value).slice(0, 4096) });
  };
  const flush = () => {
    for (const el of [...pending.keys()]) report(el);
  };

  addEventListener(
    'input',
    (ev) => {
      const el = trusted(ev) && target(ev);
      if (el && typed(el)) pending.set(el, el.value);
    },
    true,
  );
  addEventListener(
    'change',
    (ev) => {
      const el = trusted(ev) && target(ev);
      if (!el) return;
      if (typed(el)) {
        pending.set(el, el.value);
        report(el);
      } else if (el.localName === 'select') {
        send({ t: 'select', ...selector(el), ...field(el), value: String(el.value).slice(0, 4096) });
      } else if (ticked(el)) {
        send({ t: 'check', ...selector(el), ...field(el), checked: el.checked });
      }
    },
    true,
  );

  let lastEnter = 0;
  const CLICKABLE =
    'a[href],button,summary,label,input[type=submit],input[type=button],input[type=image],input[type=reset],' +
    '[role=button],[role=link],[role=tab],[role=menuitem],[role=option],[onclick]';
  addEventListener(
    'click',
    (ev) => {
      const el = trusted(ev) && target(ev);
      // A click into a field only puts the cursor there; a tick box reports its change.
      if (!el || typed(el) || ticked(el) || el.localName === 'select' || el.localName === 'option') return;
      let hit = el.closest(CLICKABLE);
      if (hit && hit.localName === 'label') {
        // The browser clicks the label's field next, which reports for itself.
        if (hit.control || hit.querySelector('input,select,textarea,button')) return;
        hit = null;
      }
      if (!hit) {
        if (getComputedStyle(el).cursor !== 'pointer') return;
        hit = el;
      }
      // Enter in a field makes the browser click the form's button: the key is the step.
      if (ev.detail === 0 && Date.now() - lastEnter < 500) return;
      flush();
      send({ t: 'click', ...selector(hit), tag: hit.localName, label: label(hit) });
    },
    true,
  );
  addEventListener(
    'keydown',
    (ev) => {
      const el = trusted(ev) && ev.key === 'Enter' && !ev.isComposing && target(ev);
      if (!el || el.localName !== 'input' || !typed(el)) return;
      lastEnter = Date.now();
      pending.set(el, el.value);
      flush();
      send({ t: 'press', key: 'Enter', ...selector(el), ...field(el) });
    },
    true,
  );
  addEventListener('submit', flush, true);
  addEventListener('pagehide', flush, true);
})();
