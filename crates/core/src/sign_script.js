// What a Postman pre-request script finds around it: `pm`, the older `postman` and
// `request`, CryptoJS, and a few of the modules Postman's sandbox offers. Bytes travel
// as hex through the native helpers, the only way out of this script.
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

  // ---- bytes ----
  const encoders = {
    Hex: { stringify: (w) => w.__hex, parse: (s) => new WordArray(String(s).toLowerCase()) },
    Base64: { stringify: (w) => __hexToB64(w.__hex), parse: (s) => new WordArray(__b64ToHex(String(s))) },
    Base64url: {
      stringify: (w) => __hexToB64(w.__hex).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
      parse: (s) => new WordArray(__b64ToHex(String(s).replace(/-/g, "+").replace(/_/g, "/"))),
    },
    Utf8: { stringify: (w) => __hexToUtf8(w.__hex), parse: (s) => new WordArray(__utf8ToHex(String(s))) },
    Latin1: { stringify: (w) => __hexToLatin1(w.__hex), parse: (s) => new WordArray(__latin1ToHex(String(s))) },
  };

  function WordArray(hex) {
    this.__hex = hex;
    this.sigBytes = hex.length / 2;
  }
  WordArray.prototype.toString = function (enc) {
    if (typeof enc === "string") {
      const named = { hex: "Hex", base64: "Base64", base64url: "Base64url", utf8: "Utf8", "utf-8": "Utf8", latin1: "Latin1", binary: "Latin1" };
      const e = encoders[named[enc.toLowerCase()]];
      if (!e) throw new Error("unknown encoding " + enc);
      return e.stringify(this);
    }
    return (enc || encoders.Hex).stringify(this);
  };
  WordArray.prototype.concat = function (o) {
    this.__hex += hexOf(o);
    this.sigBytes = this.__hex.length / 2;
    return this;
  };
  WordArray.prototype.clone = function () {
    return new WordArray(this.__hex);
  };

  function hexOf(x) {
    if (x instanceof WordArray) return x.__hex;
    return __utf8ToHex(String(x));
  }

  const hashes = { MD5: "md5", SHA1: "sha1", SHA256: "sha256", SHA384: "sha384", SHA512: "sha512" };
  const CryptoJS = { enc: encoders, lib: { WordArray: { random: (n) => new WordArray(__randomHex(n)), create: () => new WordArray("") } }, algo: {} };
  for (const name of Object.keys(hashes)) {
    const alg = hashes[name];
    CryptoJS[name] = (m) => new WordArray(__digest(alg, hexOf(m)));
    CryptoJS["Hmac" + name] = (m, k) => new WordArray(__hmac(alg, hexOf(k), hexOf(m)));
    const hasher = (key) => {
      let data = "";
      return {
        update(m) {
          data += hexOf(m);
          return this;
        },
        finalize(m) {
          if (m !== undefined) data += hexOf(m);
          return new WordArray(key === undefined ? __digest(alg, data) : __hmac(alg, hexOf(key), data));
        },
      };
    };
    CryptoJS.algo[name] = { __alg: alg, __make: hasher, create: () => hasher() };
  }
  CryptoJS.algo.HMAC = { create: (a, k) => a.__make(k) };

  const Buffer = {
    from(x, enc) {
      if (x instanceof WordArray) return x.clone();
      const named = { hex: "Hex", base64: "Base64", base64url: "Base64url", latin1: "Latin1", binary: "Latin1" };
      return (encoders[named[String(enc).toLowerCase()]] || encoders.Utf8).parse(x);
    },
  };

  function nodeCrypto() {
    const make = (compute) => {
      let data = "";
      return {
        update(m) {
          data += hexOf(m);
          return this;
        },
        digest(enc) {
          const w = new WordArray(compute(data));
          return enc ? w.toString(enc) : w;
        },
      };
    };
    const alg = (a) => String(a).toLowerCase().replace("-", "");
    return {
      createHash: (a) => make((d) => __digest(alg(a), d)),
      createHmac: (a, k) => make((d) => __hmac(alg(a), hexOf(k), d)),
      randomBytes: (n) => new WordArray(__randomHex(n)),
      randomUUID: uuid,
    };
  }

  function uuid() {
    const h = __randomHex(16);
    return [h.slice(0, 8), h.slice(8, 12), "4" + h.slice(13, 16), "89ab"[parseInt(h[16], 16) & 3] + h.slice(17, 20), h.slice(20, 32)].join("-");
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
  global.CryptoJS = CryptoJS;
  global.Buffer = Buffer;
  global.btoa = (s) => __hexToB64(__latin1ToHex(String(s)));
  global.atob = (s) => __hexToLatin1(__b64ToHex(String(s)));
  global.console = { log: none, info: none, warn: none, error: none, debug: none, trace: none };
  global.setTimeout = (f) => {
    f();
    return 0;
  };
  global.clearTimeout = none;
  global.require = (name) => {
    switch (String(name)) {
      case "crypto-js":
        return CryptoJS;
      case "crypto":
        return nodeCrypto();
      case "uuid":
        return { v4: uuid };
      case "btoa":
        return global.btoa;
      case "atob":
        return global.atob;
    }
    const part = String(name).match(/^crypto-js\/(hmac-)?(md5|sha1|sha256|sha384|sha512)$/);
    if (part) return CryptoJS[(part[1] ? "Hmac" : "") + part[2].toUpperCase()];
    const enc = String(name).match(/^crypto-js\/enc-(hex|base64|utf8|latin1)$/);
    if (enc) return encoders[{ hex: "Hex", base64: "Base64", utf8: "Utf8", latin1: "Latin1" }[enc[1]]];
    throw new Error("__unsupported:require('" + name + "')");
  };
  global.__finish = () =>
    JSON.stringify({
      headers: headerItems.map((h) => [h.key, h.value]),
      query: queryString(),
      set: Array.from(set),
    });
})(globalThis);
