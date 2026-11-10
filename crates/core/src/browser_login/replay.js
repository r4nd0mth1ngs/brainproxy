// Runs in every document of the browser a recorded login is replayed in: finds the elements
// the recorded steps name and tells when the page has stopped changing.
(() => {
  if (window.__bpl) return;
  let last = performance.now();
  try {
    new MutationObserver(() => {
      last = performance.now();
    }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  } catch (_) {}
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
  // The element a step names: the one that shows, or (`any`) one that doesn't, such as a
  // tick box drawn by its label.
  const find = (css, text, any) => {
    let list;
    try {
      list = [...document.querySelectorAll(css)];
    } catch (_) {
      return null;
    }
    if (text != null) list = list.filter((el) => label(el) === text);
    return list.find(visible) || (any && list[0]) || null;
  };
  const setter = (el) => {
    const proto =
      el.localName === 'textarea' ? HTMLTextAreaElement.prototype : el.localName === 'select' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    return Object.getOwnPropertyDescriptor(proto, 'value').set;
  };
  const changed = (el) => {
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  window.__bpl = {
    // [readyState, milliseconds since the DOM last changed]
    quiet: () => [document.readyState, performance.now() - last],
    href: () => location.href,
    // Where to click the element, or null while it isn't there (or isn't shown yet).
    locate(css, text) {
      const el = find(css, text);
      if (!el) return null;
      el.scrollIntoView({ block: 'center', inline: 'center' });
      const r = el.getBoundingClientRect();
      const [x, y] = [r.left + r.width / 2, r.top + r.height / 2];
      const at = document.elementFromPoint(x, y);
      return { x, y, hit: !!at && (at === el || el.contains(at) || at.contains(el)), tag: el.localName, off: !!el.disabled };
    },
    // Puts the cursor in a field with its content selected, so typing replaces it.
    focus(css, text) {
      const el = find(css, text);
      if (!el) return false;
      el.focus();
      try {
        if (el.select) el.select();
      } catch (_) {}
      return document.activeElement === el;
    },
    // Sets a field no cursor goes into (a select, a field typing can't reach).
    set(css, text, value) {
      const el = find(css, text, true);
      if (!el) return false;
      setter(el).call(el, value);
      changed(el);
      return true;
    },
    check(css, text, on) {
      const el = find(css, text, true);
      if (!el) return false;
      if (el.checked !== on) el.click();
      return true;
    },
    click(css, text) {
      const el = find(css, text);
      if (!el) return false;
      el.click();
      return true;
    },
    text: () => (document.documentElement ? document.documentElement.outerHTML.slice(0, 2000000) : ''),
  };
})();
