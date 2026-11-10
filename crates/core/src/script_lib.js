// What every script brainproxy runs finds around it: CryptoJS, a Buffer.from, btoa and atob,
// and a few of the modules Postman's sandbox offers. Bytes travel as hex through the native
// helpers, the only way out of a script.
(function (global) {
  "use strict";
  const none = () => undefined;

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
})(globalThis);
