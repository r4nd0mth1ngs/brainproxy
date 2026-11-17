// brainproxy browser crawl: runs in every document before the page's own scripts
// (Page.addScriptToEvaluateOnNewDocument). It notes client-side routes, window.open URLs,
// elements given click handlers and DOM activity, silences dialogs, and lets the crawler
// list links, clickable elements, forms and fields, fill fields and click elements.
(() => {
  if (window.__bp) return;
  // The page can reach __bp, so it is frozen and holds only functions; state stays in here,
  // and what it returns is limited, so a page can't hand back a huge snapshot.
  const bp = {};
  const st = {
    routes: [],
    opened: [],
    listeners: new WeakSet(),
    lastMutation: 0,
    fieldEls: [],
    // Comboboxes and listboxes chosen in, the listboxes they opened, and the option to click.
    chosen: new WeakSet(),
    lists: new WeakSet(),
    option: null,
  };
  Object.defineProperty(window, "__bp", { value: bp, enumerable: false });
  const now = () => performance.now();
  st.lastMutation = now();
  const MAX_NOTED = 200;
  const MAX_URL = 4096;
  const short = (s, n = 256) => String(s || "").slice(0, n);
  const note = (list, url) => {
    if (list.length < MAX_NOTED && url.length <= MAX_URL) list.push(url);
  };
  const abs = (u) => {
    try {
      return new URL(String(u), location.href).href;
    } catch (e) {
      return null;
    }
  };

  // Elements with click-like listeners (before the page adds any).
  const CLICK_EVENTS = new Set(["click", "dblclick", "mousedown", "mouseup", "pointerdown", "pointerup", "touchstart"]);
  const add = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    try {
      if (CLICK_EVENTS.has(type) && this instanceof Element) st.listeners.add(this);
    } catch (e) {}
    return add.call(this, type, fn, opts);
  };

  // Client-side routes.
  for (const m of ["pushState", "replaceState"]) {
    const orig = history[m];
    history[m] = function (state, title, url) {
      if (url != null) {
        const a = abs(url);
        if (a) note(st.routes, a);
      }
      st.lastMutation = now();
      return orig.apply(this, arguments);
    };
  }
  addEventListener("hashchange", () => {
    note(st.routes, location.href);
    st.lastMutation = now();
  });

  // Nobody answers dialogs; confirm() says no. Pop-ups are noted, not opened.
  window.alert = () => {};
  window.confirm = () => false;
  window.prompt = () => null;
  window.print = () => {};
  window.open = function (u) {
    const a = u == null ? null : abs(u);
    if (a) note(st.opened, a);
    return null;
  };

  new MutationObserver(() => {
    st.lastMutation = now();
  }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });

  const clean = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 80);
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };
  const label = (el) =>
    clean(
      el.getAttribute("aria-label") ||
        el.innerText ||
        (el.tagName === "INPUT" ? el.value : "") ||
        el.getAttribute("title") ||
        el.getAttribute("alt") ||
        (el.querySelector("img[alt]") || {}).alt ||
        "",
    );
  // A real link is followed by loading its URL; "#" and javascript: links are clicked.
  const realLink = (el) => {
    const h = el.getAttribute("href");
    return h != null && h.trim() !== "" && !/^\s*(#\s*$|javascript:)/i.test(h);
  };

  bp.quiet = () => [document.readyState, now() - st.lastMutation];

  // Each link with its labels, so destructive ones ("Delete account") can be left alone.
  bp.links = () => {
    const out = new Map();
    const put = (el, v) => {
      if (!v || out.size >= 500 || /^\s*(javascript:|mailto:|tel:|data:|blob:)/i.test(v)) return;
      const href = abs(v.trim());
      if (!href || href.length > MAX_URL || out.has(href)) return;
      out.set(href, {
        tag: el.tagName.toLowerCase(),
        text: el.tagName === "IFRAME" || el.tagName === "FRAME" ? "" : label(el),
        id: short(el.id),
        name: short(el.getAttribute("name")),
        class: clean(typeof el.className === "string" ? el.className : ""),
        title: clean(el.getAttribute("title")),
        href,
      });
    };
    for (const el of document.querySelectorAll("a[href],area[href]")) put(el, el.getAttribute("href"));
    for (const el of document.querySelectorAll("[data-href],[data-url],[routerlink],[ng-href]"))
      put(el, el.getAttribute("data-href") || el.getAttribute("data-url") || el.getAttribute("routerlink") || el.getAttribute("ng-href"));
    for (const el of document.querySelectorAll("iframe[src],frame[src]")) put(el, el.getAttribute("src"));
    return [...out.values()].slice(0, 500);
  };

  const CLICKY =
    "a,button,summary,[onclick],input[type=button],input[type=submit],input[type=image]," +
    "[role=button],[role=link],[role=menuitem],[role=menuitemcheckbox],[role=menuitemradio]," +
    "[role=tab],[role=option],[role=treeitem],[role=switch]";
  const clickables = () => {
    const found = [];
    const seen = new Set();
    const put = (el) => {
      if (!seen.has(el)) {
        seen.add(el);
        found.push(el);
      }
    };
    for (const el of document.querySelectorAll(CLICKY)) if (!(el.tagName === "A" && realLink(el))) put(el);
    const semantic = new Set(found);
    const all = document.body ? document.body.getElementsByTagName("*") : [];
    let n = 0;
    for (const el of all) {
      if (++n > 5000) break;
      if (seen.has(el)) continue;
      if (st.listeners.has(el) || typeof el.onclick === "function") {
        put(el);
        continue;
      }
      // The outermost element of a region with a pointer cursor (frameworks that
      // delegate events from the root leave no other trace).
      const p = el.parentElement;
      if (getComputedStyle(el).cursor === "pointer" && !(p && getComputedStyle(p).cursor === "pointer")) put(el);
    }
    // Found by listener or cursor only: not a page-sized container (frameworks listen
    // on the root), and not inside another clickable (clicking that one is enough).
    const area = innerWidth * innerHeight;
    for (const el of found) {
      const r = el.getBoundingClientRect();
      if (!semantic.has(el) && (el === document.body || r.width * r.height > 0.5 * area)) seen.delete(el);
    }
    return found.filter((el) => {
      const link = el.closest("a[href]");
      if (!seen.has(el) || el.disabled || (link && realLink(link)) || !visible(el)) return false;
      if (semantic.has(el)) return true;
      for (let a = el.parentElement, i = 0; a && i < 6; a = a.parentElement, i++) if (seen.has(a)) return false;
      return true;
    });
  };

  const describe = (el) => {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    const form = el.form || el.closest("form");
    const submits =
      !!form &&
      ((tag === "button" && (el.getAttribute("type") || "submit").toLowerCase() === "submit") ||
        (tag === "input" && (type === "submit" || type === "image")));
    return {
      tag,
      role: (el.getAttribute("role") || "").toLowerCase(),
      type,
      text: label(el),
      id: short(el.id),
      name: short(el.getAttribute("name")),
      class: clean(typeof el.className === "string" ? el.className : ""),
      title: clean(el.getAttribute("title")),
      href: short(el.getAttribute("href"), MAX_URL),
      submits,
      action: submits ? short(form.action || location.href, MAX_URL) : "",
    };
  };

  // Each clickable with a key: its description plus its position among equal ones.
  const keyed = () => {
    const counts = {};
    return clickables()
      .slice(0, 300)
      .map((el) => {
        const d = describe(el);
        const sig = [d.tag, d.role, d.type, d.text, d.id].join("|");
        const n = (counts[sig] = (counts[sig] || 0) + 1);
        d.key = sig + "#" + n;
        return [el, d];
      });
  };
  const find = (key) => (keyed().find(([, d]) => d.key === key) || [])[0];

  const forms = () =>
    [...document.forms].slice(0, 100).map((f, i) => ({
      key: "form#" + (i + 1),
      action: short(f.action || location.href, MAX_URL),
      method: (f.getAttribute("method") || "get").toLowerCase(),
      has_submit: [...f.elements].some((e) => {
        const t = (e.getAttribute("type") || (e.tagName === "BUTTON" ? "submit" : "")).toLowerCase();
        return (t === "submit" || t === "image") && visible(e);
      }),
    }));

  bp.snapshot = () => {
    // Everything opens in this tab.
    for (const el of document.querySelectorAll("form[target],a[target]")) el.removeAttribute("target");
    return {
      url: location.href,
      title: short(document.title),
      links: bp.links(),
      routes: st.routes.splice(0),
      opened: st.opened.splice(0),
      clickables: keyed().map(([, d]) => d),
      forms: forms(),
    };
  };

  // Scrolls the element into view; where to click it and whether it is on top there.
  bp.locate = (key) => {
    const el = find(key);
    return el ? point(el) : null;
  };
  bp.click = (key) => {
    const el = find(key);
    if (!el) return false;
    el.click();
    return true;
  };
  bp.submit = (key) => {
    const f = document.forms[Number(key.split("#")[1]) - 1];
    if (!f) return false;
    f.removeAttribute("target");
    if (f.requestSubmit) f.requestSubmit();
    else f.submit();
    return true;
  };

  // An arithmetic captcha's sum ("What is 3+4*2 ?"), for a field labelled like one: the
  // expression is an element's whole text near the field. "/" isn't an operator, so a
  // "0/160" character counter isn't taken for one.
  const CAPTCHA = /captcha|result|answer|solve|sum\b|math|calculat|human|robot/i;
  const ARITH = /^\s*(?:what\s+is\s+)?(-?\d{1,6}(?:\s*[-+*×x÷]\s*-?\d{1,6}){1,5})\s*[=?]?\s*$/i;
  const solve = (expr) => {
    // Each step reads a number and the operator after it; "*", "×", "x" and "÷" bind before
    // "+" and "-".
    const step = /(-?\d+)([-+*×x÷]?)/iy;
    const s = expr.replace(/\s+/g, "");
    const terms = [];
    let [n, op] = [null, "+"];
    for (let m; step.lastIndex < s.length && (m = step.exec(s)); ) {
      const v = Number(m[1]);
      if (n === null || op === "+" || op === "-") {
        if (n !== null) terms.push(n);
        n = op === "-" ? -v : v;
      } else n = op === "÷" ? n / v : n * v;
      op = m[2].toLowerCase();
      if (!op) break;
    }
    if (n === null || step.lastIndex !== s.length) return "";
    const r = [...terms, n].reduce((a, b) => a + b, 0);
    return Number.isFinite(r) && Number.isInteger(r) ? String(r) : "";
  };
  const captchaAnswer = (el) => {
    const labels = el.labels ? [...el.labels].map((l) => l.innerText) : [];
    const said = [el.name, el.id, el.getAttribute("aria-label"), el.placeholder, ...labels].join(" ");
    if (!CAPTCHA.test(said)) return "";
    for (let a = el.parentElement, i = 0; a && i < 6; a = a.parentElement, i++) {
      let n = 0;
      for (const t of a.getElementsByTagName("*")) {
        if (++n > 500) break;
        if (t.children.length > 1 || /^(SCRIPT|STYLE|TEXTAREA|SELECT|OPTION)$/.test(t.tagName)) continue;
        const m = ARITH.exec(t.textContent || "");
        if (m && visible(t)) {
          const v = solve(m[1]);
          if (v) return v;
        }
      }
    }
    return "";
  };

  // ARIA comboboxes and listboxes that aren't native fields (Angular Material's mat-select,
  // headless UI libraries): picked by opening them and clicking an option, as a person does.
  const CHOOSY = "[role=combobox],[role=listbox]";
  const isOption = (o) => o.getAttribute("aria-disabled") !== "true" && !o.hasAttribute("disabled") && visible(o) && label(o);
  const optionsOf = (el) => {
    let list = el.getAttribute("role") === "listbox" ? el : null;
    for (const e of [el, ...el.querySelectorAll("[aria-controls],[aria-owns]")]) {
      if (list) break;
      const ids = `${e.getAttribute("aria-controls") || ""} ${e.getAttribute("aria-owns") || ""}`.split(/\s+/);
      for (const id of ids) if (id && (list = document.getElementById(id))) break;
    }
    // Without a link from the combobox, the listbox that opened is the visible one.
    const lists = list ? [list] : [...document.querySelectorAll("[role=listbox]")].filter((l) => l !== el && visible(l));
    return lists.flatMap((l) => [...l.querySelectorAll("[role=option]")].slice(0, 100)).filter(isOption);
  };
  const point = (el) => {
    el.scrollIntoView({ block: "center", inline: "center" });
    const r = el.getBoundingClientRect();
    const x = r.left + r.width / 2;
    const y = r.top + r.height / 2;
    const hit = document.elementFromPoint(x, y);
    return { x, y, hit: !!hit && (hit === el || el.contains(hit)) };
  };

  // A native box or slider a component library draws its own control over keeps it see-through
  // (Material's checkbox, radio and slider): it is still the field the form reads.
  const drawnOver = (el) => {
    if (el.tagName !== "INPUT" || !/^(checkbox|radio|range)$/i.test(el.type)) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width >= 1 && r.height >= 1 && s.visibility !== "hidden" && s.display !== "none";
  };

  bp.fields = () => {
    st.fieldEls = [];
    for (const el of document.querySelectorAll("input,textarea,select," + CHOOSY)) {
      if (st.fieldEls.length >= 200) break;
      const choosy = !/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName);
      // A listbox inside a combobox (or one a combobox opened) is chosen through that combobox.
      if (choosy && el.getAttribute("role") === "listbox" && (el.closest("[role=combobox]") || st.lists.has(el))) continue;
      const off = el.disabled || el.readOnly || el.getAttribute("aria-disabled") === "true" || el.getAttribute("aria-readonly") === "true";
      if (!off && (visible(el) || drawnOver(el))) st.fieldEls.push(el);
    }
    return st.fieldEls.map((el, i) => {
      const choosy = !/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName);
      return {
        i,
        tag: el.tagName.toLowerCase(),
        type: choosy ? el.getAttribute("role") : short(el.type).toLowerCase(),
        name: short(el.name || el.id || el.getAttribute("aria-label") || el.placeholder),
        value: choosy ? "" : short(el.value),
        required: !!el.required || el.getAttribute("aria-required") === "true",
        checked: !!el.checked,
        // A listbox with an option already selected, or a combobox this document has chosen in.
        chosen: choosy && (st.chosen.has(el) || !!el.querySelector("[role=option][aria-selected=true]")),
        options: el.tagName === "SELECT" ? [...el.options].slice(0, 50).map((o) => short(o.value)) : [],
        max: el.type === "range" ? short(el.max || "100") : "",
        answer: el.tagName === "INPUT" && !choosy ? captchaAnswer(el) : "",
      };
    });
  };
  // Sets values the way typing does, so frameworks that track input events see them; leaving
  // the field (blur) is what some forms wait for before checking a value or showing more fields.
  bp.setFields = (pairs) => {
    for (const [i, v] of pairs) {
      const el = st.fieldEls[i];
      if (!el || !el.isConnected) continue;
      if (v === true) {
        if (!el.checked) el.click();
        continue;
      }
      const proto =
        el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : el.tagName === "SELECT" ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      el.dispatchEvent(new FocusEvent("blur"));
      el.dispatchEvent(new FocusEvent("focusout", { bubbles: true }));
    }
    return true;
  };
  // A combobox or listbox to choose in: where to click it to open it (a listbox's options are
  // already there). It counts as chosen from now on, so a box that never opens isn't retried.
  bp.openField = (i) => {
    const el = st.fieldEls[i];
    if (!el || !el.isConnected) return null;
    st.chosen.add(el);
    if (el.getAttribute("role") === "listbox") return { x: 0, y: 0, hit: false, open: true };
    return point(el);
  };
  bp.clickField = (i) => {
    const el = st.fieldEls[i];
    if (!el || !el.isConnected) return false;
    el.click();
    return true;
  };
  // The first option of the open combobox or listbox: where to click it.
  bp.pickOption = (i) => {
    const el = st.fieldEls[i];
    if (!el || !el.isConnected) return null;
    const o = optionsOf(el)[0];
    if (!o) return null;
    st.option = o;
    const list = o.closest("[role=listbox]");
    if (list) st.lists.add(list);
    return { ...point(o), text: label(o) };
  };
  bp.clickOption = () => {
    const o = st.option;
    st.option = null;
    if (!o || !o.isConnected) return false;
    o.click();
    return true;
  };

  Object.freeze(bp);
})();
