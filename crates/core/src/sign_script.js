// What a Postman pre-request script finds around it, on top of script_lib.js: `pm`, and the
// older `postman` and `request`.
(function (global) {
  "use strict";
  const input = JSON.parse(__input);
  const store = new Map(input.vars);
  const set = new Map();

  function unsupported(name) {
    return function () {
      throw new Error("__unsupported:" + name);
    };
  }

  // ---- variables ----
  function replaceIn(text) {
    return String(text).replace(/\{\{([^{}]+)\}\}/g, (all, name) => {
      const v = store.get(name.trim());
      return v === undefined ? all : v;
    });
  }
  const scope = {
    get: (k) => store.get(String(k)),
    set(k, v) {
      const text = v === undefined || v === null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
      store.set(String(k), text);
      set.set(String(k), text);
    },
    has: (k) => store.has(String(k)),
    unset(k) {
      store.delete(String(k));
      set.delete(String(k));
    },
    clear() {},
    toObject: () => Object.fromEntries(store),
    replaceIn,
  };

  // ---- the request ----
  function list(items, sameKey) {
    const same = (a, b) => (sameKey ? sameKey(a, b) : a === b);
    const find = (k) => items.find((i) => same(i.key, String(k)));
    const item = (k, v) => (typeof k === "object" && k !== null ? { key: String(k.key), value: k.value === undefined || k.value === null ? "" : String(k.value) } : { key: String(k), value: v === undefined || v === null ? "" : String(v) });
    const out = {
      add(k, v) {
        items.push(item(k, v));
      },
      append(k, v) {
        items.push(item(k, v));
      },
      upsert(k, v) {
        const n = item(k, v);
        const old = find(n.key);
        if (old) old.value = n.value;
        else items.push(n);
      },
      remove(k) {
        const name = typeof k === "object" && k !== null ? k.key : k;
        for (let i = items.length - 1; i >= 0; i--) if (same(items[i].key, String(name))) items.splice(i, 1);
      },
      get: (k) => (find(k) || {}).value,
      one: (k) => find(k),
      has: (k) => find(k) !== undefined,
      all: () => items.slice(),
      each: (f) => items.slice().forEach(f),
      map: (f) => items.map(f),
      filter: (f) => items.filter(f),
      find: (f) => items.find(f),
      toObject: () => Object.fromEntries(items.map((i) => [i.key, i.value])),
      count: () => items.length,
      clear: () => items.splice(0, items.length),
      toString: () => items.map((i) => i.key + "=" + i.value).join("&"),
    };
    return out;
  }

  const r = input.request;
  const noCase = (a, b) => a.toLowerCase() === b.toLowerCase();
  const headerItems = r.headers.map(([key, value]) => ({ key, value }));
  const decoded = (s) => {
    try {
      return decodeURIComponent(s.replace(/\+/g, " "));
    } catch (e) {
      return s;
    }
  };
  const queryItems = r.query
    ? r.query.split("&").filter(Boolean).map((p) => {
        const at = p.indexOf("=");
        const key = decoded(at < 0 ? p : p.slice(0, at));
        const value = at < 0 ? "" : decoded(p.slice(at + 1));
        return { key, value, __raw: p, __was: key + "\u0000" + value };
      })
    : [];
  const queryString = () =>
    queryItems
      .map((i) => (i.__raw !== undefined && i.__was === i.key + "\u0000" + i.value ? i.__raw : encodeURIComponent(i.key) + "=" + encodeURIComponent(i.value)))
      .join("&");
  const defaultPort = r.scheme === "https" ? "443" : "80";
  const portText = String(r.port) === defaultPort ? "" : ":" + r.port;
  const url = {
    protocol: r.scheme,
    host: r.host.split("."),
    port: String(r.port) === defaultPort ? undefined : String(r.port),
    path: r.path.split("/").slice(1),
    query: list(queryItems),
    getHost: () => r.host,
    getRemote: () => r.host + portText,
    getPath: () => r.path,
    getQueryString: queryString,
    getPathWithQuery: () => r.path + (queryItems.length ? "?" + queryString() : ""),
    toString: () => r.scheme + "://" + r.host + portText + url.getPathWithQuery(),
  };
  const form = /x-www-form-urlencoded/i.test((headerItems.find((h) => noCase(h.key, "content-type")) || {}).value || "");
  const body = {
    mode: r.body === "" ? undefined : form ? "urlencoded" : "raw",
    raw: r.body,
    urlencoded: form ? list(r.body.split("&").filter(Boolean).map((p) => {
      const at = p.indexOf("=");
      return { key: decoded(at < 0 ? p : p.slice(0, at)), value: at < 0 ? "" : decoded(p.slice(at + 1)) };
    })) : undefined,
    isEmpty: () => r.body === "",
    toString: () => r.body,
    toJSON: () => r.body,
  };
  const pmRequest = {
    id: "",
    name: "",
    headers: list(headerItems, noCase),
    addHeader(h) {
      this.headers.add(h);
    },
    upsertHeader(h) {
      this.headers.upsert(h);
    },
    removeHeader(k) {
      this.headers.remove(k);
    },
    addQueryParams(q) {
      (Array.isArray(q) ? q : [q]).forEach((p) => url.query.add(p));
    },
  };
  const readOnly = (o, name, value) =>
    Object.defineProperty(o, name, {
      get: () => value,
      set: unsupported("changing pm.request." + name),
      enumerable: true,
    });
  readOnly(pmRequest, "method", r.method);
  readOnly(pmRequest, "url", url);
  // Always there: a script that hashes the body runs on bodyless requests too.
  readOnly(pmRequest, "body", body);

  const none = () => undefined;
  global.pm = {
    environment: scope,
    collectionVariables: scope,
    globals: scope,
    variables: scope,
    iterationData: scope,
    request: pmRequest,
    info: { eventName: "prerequest", iteration: 0, iterationCount: 1, requestName: "", requestId: "" },
    execution: { location: [], setNextRequest: none, skipRequest: unsupported("pm.execution.skipRequest") },
    sendRequest: unsupported("pm.sendRequest"),
    cookies: { get: unsupported("pm.cookies"), has: unsupported("pm.cookies"), toObject: unsupported("pm.cookies"), jar: unsupported("pm.cookies.jar") },
    vault: { get: unsupported("pm.vault"), set: unsupported("pm.vault"), unset: unsupported("pm.vault") },
    test: none,
    expect: unsupported("pm.expect"),
    require: (n) => global.require(n),
  };
  global.postman = {
    getEnvironmentVariable: scope.get,
    setEnvironmentVariable: scope.set,
    clearEnvironmentVariable: scope.unset,
    getGlobalVariable: scope.get,
    setGlobalVariable: scope.set,
    clearGlobalVariable: scope.unset,
    setNextRequest: none,
  };
  global.environment = Object.fromEntries(store);
  global.globals = global.environment;
  global.data = {};
  global.tests = {};
  global.request = {
    method: r.method,
    url: url.toString(),
    headers: Object.fromEntries(r.headers),
    data: r.body,
  };
  global.__finish = () =>
    JSON.stringify({
      headers: headerItems.map((h) => [h.key, h.value]),
      query: queryString(),
      set: Array.from(set),
    });
})(globalThis);
