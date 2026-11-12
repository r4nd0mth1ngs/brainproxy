// How a hook script's function is called: what it is given is parsed and frozen, and what it
// returns is put in the one shape its kind allows, or refused. This evaluates to a function
// that takes the script's function and its kind and gives the caller two entry points.
(function () {
  "use strict";
  const parse = JSON.parse;
  const stringify = JSON.stringify;
  const isArray = Array.isArray;
  const freeze = (o) => {
    if (o !== null && typeof o === "object" && !Object.isFrozen(o)) {
      Object.freeze(o);
      for (const k of Object.keys(o)) freeze(o[k]);
    }
    return o;
  };
  const kindOf = (v) => (v === null ? "null" : isArray(v) ? "an array" : typeof v === "object" ? "an object" : typeof v === "undefined" ? "nothing" : "a " + typeof v);
  // Bytes a script gives back: a string, { base64 }, or null to leave things as they are.
  const bytes = (out) => {
    if (typeof out === "string") return { text: out };
    if (out === null) return { keep: true };
    if (typeof out === "object" && typeof out.then === "function") throw new TypeError("it returned a promise: return the value itself");
    if (typeof out === "object" && !isArray(out) && typeof out.base64 === "string") return { base64: out.base64 };
    throw new TypeError("it returned " + kindOf(out) + ": return a string, { base64 } or null");
  };
  const findings = (out) => {
    if (out === undefined || out === null) return { findings: [] };
    if (typeof out === "object" && typeof out.then === "function") throw new TypeError("it returned a promise: return the value itself");
    const list = isArray(out) ? out : [out];
    for (const f of list) {
      if (f === null || typeof f !== "object" || isArray(f)) throw new TypeError("it returned " + kindOf(f) + " as a finding: return objects with a name");
    }
    return { findings: list };
  };
  // What a request rule's script decides: nothing (send it), or one of { request } (send it
  // rewritten), { block } (don't send it) and { response } (don't send it: answer with this).
  // The parts are read, and refused if wrong, by brainproxy.
  const verdict = (out) => {
    if (out === undefined || out === null) return { keep: true };
    if (typeof out === "object" && typeof out.then === "function") throw new TypeError("it returned a promise: return the value itself");
    if (typeof out !== "object" || isArray(out)) throw new TypeError("it returned " + kindOf(out) + ": return nothing, { request }, { block } or { response }");
    const keys = ["request", "block", "response"].filter((k) => out[k] !== undefined && out[k] !== null);
    if (keys.length === 0) throw new TypeError("it returned an object with no request, block or response");
    if (keys.length > 1) throw new TypeError("it returned " + keys.join(" and ") + ": return one of them");
    const key = keys[0];
    const value = out[key];
    if (key === "block") {
      if (value === true) return { block: "" };
      if (typeof value !== "string") throw new TypeError("its block is " + kindOf(value) + ": give the reason as a string");
      return { block: value };
    }
    if (typeof value !== "object" || isArray(value)) throw new TypeError("its " + key + " is " + kindOf(value) + ": return an object");
    return key === "request" ? { request: value } : { response: value };
  };
  return function (fn, kind) {
    let cx = freeze({});
    return {
      cx(json) {
        cx = freeze(parse(json));
      },
      call(json) {
        const item = freeze(parse(json));
        switch (kind) {
          case "replace":
            return stringify(bytes(fn(item, cx)));
          case "process":
            return stringify(bytes(fn(item.text, freeze({ ...cx, ...item }))));
          case "request":
            return stringify(verdict(fn(item, cx)));
          default:
            return stringify(findings(fn(item)));
        }
      },
    };
  };
})()
