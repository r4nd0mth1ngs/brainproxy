// cURL commands in and out of Replay. `parseCurl` turns a pasted command (a POSIX shell line,
// or Windows cmd as Chrome's "Copy as cURL (cmd)" writes it) into a raw request and its target;
// `toCurl` writes a raw request as a POSIX shell command with every value single-quoted (and
// control or non-UTF-8 bytes written with printf), so header values and bodies that came from a
// target can't run anything in the shell.
// Both work on byte strings (one char per byte) inside, so binary bodies survive.

// With its extension, so node --test can load this module (as the tests import theirs).
import { textBytes } from "../api.ts";
import { splitRaw } from "./message.ts";

export class CurlError extends Error {}

/** A request read from a cURL command. */
export interface ParsedCurl {
  /** Raw HTTP request: the head with \n line endings, the body as curl would send it. */
  raw: string;
  /** scheme://host[:port], the port only when it isn't the scheme's default. */
  target: string;
  /** The URL curl would request (fragment dropped), for a tab title. */
  url: string;
  /** `raw` holds one char per byte (it isn't valid UTF-8); send it with `textBytes(raw, true)`. */
  binary: boolean;
  /** Options that were left out although they matter (a proxy, --resolve, a client certificate). */
  warnings: string[];
}

/** A request written as a cURL command. */
export interface CurlCommand {
  command: string;
  warnings: string[];
}

/** One argument longer than this fails on Linux (MAX_ARG_STRLEN is 128 KiB). */
export const CURL_ARG_WARN = 128 * 1024;
/** Bodies larger than this aren't written as a command at all (the app's own message limit). */
export const CURL_MAX_BODY = 2_000_000;

// ---------- bytes ----------

/** Text as UTF-8, one char per byte. */
function utf8(s: string): string {
  return latin1(new TextEncoder().encode(s));
}

function latin1(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return s;
}

function bytesOf(b: string): Uint8Array {
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** The text a byte string holds, or null when it isn't valid UTF-8. */
function decodeUtf8(b: string): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytesOf(b));
  } catch {
    return null;
  }
}

const decodeOr = (b: string) => decodeUtf8(b) ?? b;

// ---------- reading a command line ----------

const NAME_START = /[A-Za-z_{(0-9@*#?!$-]/;

function expansion(): never {
  throw new CurlError("The command uses shell variables or command substitution ($…, `…`); replace them with their values first.");
}

/** Words of a POSIX shell command line (sh, bash, zsh), as byte strings. */
function posixWords(src: string): string[] {
  const cs = Array.from(src);
  const words: string[] = [];
  let cur = "";
  let inWord = false;
  const lit = (s: string) => {
    cur += utf8(s);
    inWord = true;
  };
  const end = () => {
    if (inWord) words.push(cur);
    cur = "";
    inWord = false;
  };
  let i = 0;
  while (i < cs.length) {
    const c = cs[i];
    if (c === " " || c === "\t" || c === "\n") {
      end();
      i++;
    } else if (c === "\\") {
      // A backslash before a newline continues the line; before anything else it quotes it.
      if (cs[i + 1] !== "\n" && i + 1 < cs.length) lit(cs[i + 1]);
      i += 2;
    } else if (c === "'") {
      const close = cs.indexOf("'", i + 1);
      if (close < 0) throw new CurlError("Unterminated ' quote.");
      lit(cs.slice(i + 1, close).join(""));
      i = close + 1;
    } else if (c === "$" && cs[i + 1] === "'") {
      const [bytes, next] = ansiC(cs, i + 2);
      cur += bytes;
      inWord = true;
      i = next;
    } else if (c === '"') {
      let s = "";
      for (i++; ; i++) {
        if (i >= cs.length) throw new CurlError('Unterminated " quote.');
        const d = cs[i];
        if (d === '"') break;
        if (d === "\\" && i + 1 < cs.length && '$`"\\\n'.includes(cs[i + 1])) {
          if (cs[i + 1] !== "\n") s += cs[i + 1];
          i++;
        } else if (d === "$" && cs[i + 1] === "(") {
          lit(s);
          s = "";
          const [bytes, next] = printfSubst(cs, i);
          cur += bytes;
          i = next - 1;
        } else if ((d === "$" && NAME_START.test(cs[i + 1] ?? "")) || d === "`") expansion();
        else s += d;
      }
      lit(s);
      i++;
    } else if ((c === "$" && NAME_START.test(cs[i + 1] ?? "")) || c === "`") {
      // $(printf …) only inside "…", the form toCurl writes: unquoted, a shell would split
      // what it prints into words.
      expansion();
    } else if ("|&;<>()".includes(c)) {
      throw new CurlError(`Unquoted "${c}" ends the curl command in a shell: paste a single command, and quote URLs that contain & or ;.`);
    } else if (c === "#" && !inWord) {
      // A comment runs to the end of the line.
      while (i < cs.length && cs[i] !== "\n") i++;
    } else {
      lit(c);
      i++;
    }
  }
  end();
  return words;
}

/** A $'…' string from `i` (just after the opening quote): its bytes and where it ends. */
function ansiC(cs: string[], i: number): [string, number] {
  const SIMPLE: Record<string, string> = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };
  let out = "";
  const digits = (re: RegExp, max: number) => {
    let d = "";
    while (d.length < max && re.test(cs[i] ?? "")) d += cs[i++];
    return d;
  };
  while (i < cs.length) {
    const c = cs[i++];
    if (c === "'") {
      if (out.includes("\0")) throw new CurlError("A $'…' string holds a NUL byte, which a shell can't pass to curl.");
      return [out, i];
    }
    if (c !== "\\") {
      out += utf8(c);
      continue;
    }
    const n = cs[i++];
    if (n === undefined) break;
    if (n in SIMPLE) out += SIMPLE[n];
    else if (n === "x") {
      const h = digits(/[0-9a-fA-F]/, 2);
      out += h ? String.fromCharCode(parseInt(h, 16)) : "\\x";
    } else if (n === "u" || n === "U") {
      const h = digits(/[0-9a-fA-F]/, n === "u" ? 4 : 8);
      const cp = parseInt(h, 16);
      if (!h) out += "\\" + n;
      else if (cp > 0x10ffff) throw new CurlError(`\\${n}${h} isn't a Unicode character.`);
      else out += utf8(String.fromCodePoint(cp));
    } else if (n === "c") {
      const ch = cs[i++] ?? "";
      out += String.fromCharCode(ch.toUpperCase().charCodeAt(0) & 0x1f);
    } else if (/[0-7]/.test(n)) {
      i--;
      out += String.fromCharCode(parseInt(digits(/[0-7]/, 3), 8) & 0xff);
    } else out += "\\" + utf8(n);
  }
  throw new CurlError("Unterminated $' quote.");
}

/** `$(printf '…')`, the one command substitution toCurl writes: its bytes and where it ends. */
function printfSubst(cs: string[], i: number): [string, number] {
  const open = "$(printf '";
  if (cs.slice(i, i + open.length).join("") !== open) expansion();
  const close = cs.indexOf("'", i + open.length);
  if (close < 0 || cs[close + 1] !== ")") expansion();
  const bytes = printfBytes(utf8(cs.slice(i + open.length, close).join("")));
  if (bytes.includes("\0")) throw new CurlError("A $(printf …) holds a NUL byte, which a shell can't pass to curl.");
  // A command substitution drops trailing newlines.
  return [bytes.replace(/\n+$/, ""), close + 2];
}

/** The bytes a printf format prints: its escapes and %%, nothing else (no conversions). */
function printfBytes(fmt: string): string {
  const SIMPLE: Record<string, string> = { "\\": "\\", a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" };
  let out = "";
  for (let i = 0; i < fmt.length; ) {
    const c = fmt[i++];
    if (c === "%") {
      if (fmt[i] !== "%") throw new CurlError("Only %% is read in a printf format; paste the value itself.");
      out += "%";
      i++;
    } else if (c === "\\") {
      const oct = /^[0-7]{1,3}/.exec(fmt.slice(i, i + 3));
      const n = fmt[i] ?? "";
      if (oct) {
        out += String.fromCharCode(parseInt(oct[0], 8) & 0xff);
        i += oct[0].length;
      } else if (Object.hasOwn(SIMPLE, n)) {
        out += SIMPLE[n];
        i++;
      } else throw new CurlError(`The printf escape \\${decodeOr(n)} isn't read; paste the value itself.`);
    } else out += c;
  }
  return out;
}

/**
 * Words of a Windows command line as cmd.exe and then the C runtime split it: outside double
 * quotes ^ takes the next character as is, and ^ at a line end joins the next line (Chrome
 * writes a newline in a value as ^ and two newlines); then "…" groups and \" is a quote.
 */
function cmdWords(src: string): string[] {
  const cs = Array.from(src);
  let line = "";
  let quoted = false;
  for (let i = 0; i < cs.length; i++) {
    const c = cs[i];
    if (c === "^" && !quoted) {
      if (cs[i + 1] === "\n") i++; // the line goes on; its next character is taken as is
      if (i + 1 < cs.length) line += cs[++i];
      continue;
    }
    if (c === '"') quoted = !quoted;
    // An unescaped newline would end the command in cmd; read it as a space.
    line += c === "\n" ? " " : c;
  }
  const words: string[] = [];
  let cur = "";
  let inWord = false;
  let inQuote = false;
  for (let i = 0; i < line.length; ) {
    const c = line[i];
    if (!inQuote && (c === " " || c === "\t")) {
      if (inWord) words.push(utf8(cur));
      cur = "";
      inWord = false;
      i++;
    } else if (c === "\\" && (line[i + 1] === "\\" || line[i + 1] === '"')) {
      // \\ and \" as Chrome writes them. (The C runtime keeps a \\ that isn't before a quote
      // as two backslashes, but Chrome doubles every backslash, so its commands mean one.)
      cur += line[i + 1];
      i += 2;
      inWord = true;
    } else if (c === '"') {
      if (inQuote && line[i + 1] === '"') cur += '"', i += 2;
      else inQuote = !inQuote, i++;
      inWord = true;
    } else {
      cur += c;
      inWord = true;
      i++;
    }
  }
  if (inQuote) throw new CurlError('Unterminated " quote.');
  if (inWord) words.push(utf8(cur));
  return words;
}

// ---------- options ----------

/** Options that change the request and are read below; the boolean says whether a value follows. */
const USED: Record<string, boolean> = {
  request: true,
  header: true,
  data: true,
  "data-ascii": true,
  "data-binary": true,
  "data-raw": true,
  "data-urlencode": true,
  json: true,
  form: true,
  "form-string": true,
  cookie: true,
  user: true,
  "user-agent": true,
  referer: true,
  url: true,
  range: true,
  "oauth2-bearer": true,
  "request-target": true,
  "url-query": true,
  get: false,
  head: false,
  compressed: false,
  "http1.0": false,
  "http1.1": false,
  http2: false,
  "http2-prior-knowledge": false,
  http3: false,
  "http3-only": false,
  "proto-default": true,
  "path-as-is": false,
  basic: false,
  globoff: false,
};

/** Options that don't change the request bytes (output, timing, TLS checks, retries). */
const IGNORED: Record<string, boolean> = {
  output: true,
  "output-dir": true,
  "connect-timeout": true,
  "max-time": true,
  retry: true,
  "retry-delay": true,
  "retry-max-time": true,
  "write-out": true,
  "dump-header": true,
  trace: true,
  "trace-ascii": true,
  "trace-config": true,
  stderr: true,
  "cookie-jar": true,
  "max-redirs": true,
  "limit-rate": true,
  "max-filesize": true,
  cacert: true,
  capath: true,
  crlfile: true,
  pinnedpubkey: true,
  ciphers: true,
  "tls13-ciphers": true,
  curves: true,
  "tls-max": true,
  interface: true,
  "local-port": true,
  "dns-servers": true,
  "keepalive-time": true,
  "expect100-timeout": true,
  "happy-eyeballs-timeout-ms": true,
  "speed-limit": true,
  "speed-time": true,
  "alt-svc": true,
  hsts: true,
  proto: true,
  "proto-redir": true,
  "cert-type": true,
  "key-type": true,
  pass: true,
  "etag-save": true,
  insecure: false,
  silent: false,
  "show-error": false,
  verbose: false,
  include: false,
  "show-headers": false,
  location: false,
  "location-trusted": false,
  fail: false,
  "fail-with-body": false,
  "fail-early": false,
  "no-buffer": false,
  "progress-bar": false,
  "no-progress-meter": false,
  raw: false,
  "tcp-nodelay": false,
  "tcp-fastopen": false,
  ipv4: false,
  ipv6: false,
  "remote-name": false,
  "remote-name-all": false,
  "remote-header-name": false,
  "remote-time": false,
  "create-dirs": false,
  "junk-session-cookies": false,
  "no-keepalive": false,
  "no-sessionid": false,
  "no-alpn": false,
  "no-npn": false,
  "ssl-no-revoke": false,
  "ssl-revoke-best-effort": false,
  "cert-status": false,
  tlsv1: false,
  "tlsv1.0": false,
  "tlsv1.1": false,
  "tlsv1.2": false,
  "tlsv1.3": false,
  disable: false,
  "styled-output": false,
  "retry-all-errors": false,
  "retry-connrefused": false,
  parallel: false,
  "proxy-insecure": false,
  "suppress-connect-headers": false,
  xattr: false,
};

/** Options that change where or how the request goes but not its bytes: left out with a warning. */
const WARNED: Record<string, string> = {
  proxy: "a proxy (Replay sends directly; set an upstream proxy in Settings › Connections)",
  "proxy-user": "proxy credentials",
  noproxy: "--noproxy",
  preproxy: "a pre-proxy",
  socks5: "a SOCKS proxy",
  "socks5-hostname": "a SOCKS proxy",
  socks4: "a SOCKS proxy",
  socks4a: "a SOCKS proxy",
  resolve: "--resolve (set host overrides in Settings › Connections)",
  "connect-to": "--connect-to (set host overrides in Settings › Connections)",
  cert: "a client certificate (add one in Settings › Connections)",
  key: "a client certificate key",
  "unix-socket": "a Unix socket (Replay sends to the URL's host)",
  "abstract-unix-socket": "a Unix socket (Replay sends to the URL's host)",
};

/** Options that change the request in ways brainproxy can't reproduce from the text alone. */
const REFUSED: Record<string, string> = {
  "upload-file": "-T uploads a file; paste its contents with --data-binary instead.",
  config: "-K reads options from a file; paste them instead.",
  next: "--next starts another request; paste one request at a time.",
  digest: "Digest authentication needs the server's challenge; use an auth profile (Settings › Auth) instead.",
  ntlm: "NTLM authentication needs the server's challenge; use an auth profile (Settings › Auth) instead.",
  negotiate: "Negotiate authentication isn't supported; use an auth profile instead.",
  anyauth: "--anyauth needs the server's challenge; use an auth profile (Settings › Auth) instead.",
  netrc: "--netrc reads credentials from a file; pass them with -u instead.",
  "netrc-file": "--netrc-file reads credentials from a file; pass them with -u instead.",
  "netrc-optional": "--netrc-optional reads credentials from a file; pass them with -u instead.",
};

const SHORT: Record<string, string> = {
  X: "request",
  H: "header",
  d: "data",
  F: "form",
  b: "cookie",
  u: "user",
  A: "user-agent",
  e: "referer",
  r: "range",
  G: "get",
  I: "head",
  g: "globoff",
  "0": "http1.0",
  T: "upload-file",
  K: "config",
  n: "netrc",
  ":": "next",
  k: "insecure",
  s: "silent",
  S: "show-error",
  v: "verbose",
  i: "include",
  L: "location",
  f: "fail",
  N: "no-buffer",
  "#": "progress-bar",
  o: "output",
  O: "remote-name",
  J: "remote-header-name",
  R: "remote-time",
  m: "max-time",
  w: "write-out",
  D: "dump-header",
  c: "cookie-jar",
  j: "junk-session-cookies",
  Y: "speed-limit",
  y: "speed-time",
  q: "disable",
  Z: "parallel",
  "4": "ipv4",
  "6": "ipv6",
  x: "proxy",
  U: "proxy-user",
  E: "cert",
};

/** A table's own entry: an option named like an Object property (--constructor) isn't one. */
const entry = <T,>(table: Record<string, T>, name: string): T | undefined => (Object.hasOwn(table, name) ? table[name] : undefined);

const takesValue = (name: string): boolean | undefined =>
  entry(USED, name) ?? entry(IGNORED, name) ?? (entry(WARNED, name) !== undefined || undefined);

interface Options {
  method?: string;
  urls: string[];
  headers: string[];
  data: { bytes: string; json: boolean }[];
  form: { name: string; value: string; filename?: string; type?: string }[];
  cookies: string[];
  urlQuery: string[];
  user?: string;
  userAgent?: string;
  referer?: string;
  range?: string;
  bearer?: string;
  requestTarget?: string;
  protoDefault?: string;
  version: string;
  /** --http2 (not --http2-prior-knowledge): HTTP/2 only over TLS; curl asks to upgrade over http. */
  h2Upgrade?: boolean;
  flags: Set<string>;
  warnings: string[];
}

function readOptions(words: string[], stdin?: string): Options {
  const o: Options = { urls: [], headers: [], data: [], form: [], cookies: [], urlQuery: [], version: "HTTP/1.1", flags: new Set(), warnings: [] };
  let i = 0;
  const value = (name: string, attached?: string): string => {
    if (attached !== undefined) return attached;
    if (i >= words.length) throw new CurlError(`--${name} needs a value.`);
    return words[i++];
  };
  const apply = (name: string, shown: string, attached?: string) => {
    const refused = entry(REFUSED, name);
    if (refused) throw new CurlError(refused);
    const warned = entry(WARNED, name);
    if (warned) {
      value(name, attached);
      if (!o.warnings.includes(`Left out ${warned}.`)) o.warnings.push(`Left out ${warned}.`);
      return;
    }
    const ignored = entry(IGNORED, name);
    if (ignored !== undefined) {
      if (ignored) value(name, attached);
      return;
    }
    const used = entry(USED, name);
    if (used === undefined) {
      // --no-NAME turns a switch off.
      const off = name.startsWith("no-") ? name.slice(3) : "";
      if (entry(USED, off) === false) return void o.flags.delete(off);
      if (entry(IGNORED, off) === false) return;
      throw new CurlError(`Unknown curl option ${shown}: remove it if it doesn't change the request.`);
    }
    if (!used) {
      if (name === "http1.0" || name === "http1.1") o.version = name === "http1.0" ? "HTTP/1.0" : "HTTP/1.1";
      else if (name === "http2" || name === "http2-prior-knowledge") {
        o.version = "HTTP/2";
        o.h2Upgrade = name === "http2";
      } else if (name === "http3" || name === "http3-only") o.warnings.push("brainproxy doesn't speak HTTP/3: the request is sent over HTTP/1.1.");
      else o.flags.add(name);
      return;
    }
    const v = value(name, attached);
    switch (name) {
      case "request":
        o.method = v;
        break;
      case "header":
        o.headers.push(v);
        break;
      case "data":
      case "data-ascii":
      case "data-binary":
      case "json":
        if (name === "data-binary" && v === "@-" && stdin !== undefined) {
          o.data.push({ bytes: stdin, json: false });
          o.flags.add("stdin");
          break;
        }
        if (v.startsWith("@")) throw new CurlError(`--${name} ${decodeOr(v)} reads a file; paste its contents with --data-raw instead.`);
        o.data.push({ bytes: v, json: name === "json" });
        if (name === "json") o.flags.add("json");
        break;
      case "data-raw":
        o.data.push({ bytes: v, json: false });
        break;
      case "data-urlencode":
        o.data.push({ bytes: urlencodeArg(v, "--data-urlencode"), json: false });
        break;
      case "url-query":
        o.urlQuery.push(v.startsWith("+") ? v.slice(1) : urlencodeArg(v, "--url-query"));
        break;
      case "form":
        o.form.push(formPart(v, o.warnings));
        break;
      case "form-string": {
        const eq = v.indexOf("=");
        if (eq <= 0) throw new CurlError(`--form-string needs name=value, got ${decodeOr(v)}.`);
        o.form.push({ name: v.slice(0, eq), value: v.slice(eq + 1) });
        break;
      }
      case "cookie":
        if (!v.includes("=")) throw new CurlError(`-b ${decodeOr(v)} reads cookies from a file; paste them as -b 'name=value'.`);
        o.cookies.push(v);
        break;
      case "user":
        if (!v.includes(":")) throw new CurlError("-u without a password makes curl ask for one; pass -u user:password.");
        o.user = v;
        break;
      case "user-agent":
        o.userAgent = v;
        break;
      case "referer":
        o.referer = v.replace(/;auto$/, "");
        break;
      case "url":
        o.urls.push(v);
        break;
      case "range":
        o.range = v;
        break;
      case "oauth2-bearer":
        o.bearer = v;
        break;
      case "request-target":
        o.requestTarget = v;
        break;
      case "proto-default":
        if (v !== "http" && v !== "https") throw new CurlError(`Only http and https can be sent, not --proto-default ${decodeOr(v)}.`);
        o.protoDefault = v;
        break;
    }
  };
  while (i < words.length) {
    const w = words[i++];
    if (w === "--") {
      o.urls.push(...words.slice(i));
      break;
    }
    if (w.startsWith("--")) {
      // --name=value (curl 8.16 and later): no option's name holds =, so split at the first one.
      // A switch ignores the value, as curl does.
      const eq = w.indexOf("=");
      if (eq > 2) apply(w.slice(2, eq), decodeOr(w.slice(0, eq)), w.slice(eq + 1));
      else apply(w.slice(2), decodeOr(w));
    } else if (w.length > 1 && w.startsWith("-")) {
      // Short options cluster (-sSL); a value may follow in the same word (-XPOST).
      for (let k = 1; k < w.length; k++) {
        const name = entry(SHORT, w[k]);
        if (!name) throw new CurlError(`Unknown curl option -${decodeOr(w[k])}: remove it if it doesn't change the request.`);
        if (takesValue(name)) {
          apply(name, `-${w[k]}`, w.slice(k + 1) || undefined);
          break;
        }
        apply(name, `-${w[k]}`);
      }
    } else o.urls.push(w);
  }
  return o;
}

/** Percent-encodes like curl: everything but letters, digits and -._~ */
function percentEncode(b: string): string {
  return b.replace(/[^A-Za-z0-9\-._~]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"));
}

/** --data-urlencode's forms: content, =content, name=content (name@file and @file read files). */
function urlencodeArg(v: string, flag: string): string {
  const m = /[=@]/.exec(v);
  if (m?.[0] === "@") throw new CurlError(`${flag} ${decodeOr(v)} reads a file; paste its contents instead.`);
  if (!m) return percentEncode(v);
  const name = v.slice(0, m.index);
  return (name ? name + "=" : "") + percentEncode(v.slice(m.index + 1));
}

/** One -F part: name=value, optionally "quoted", with ;type= and ;filename=. Files are refused. */
function formPart(v: string, warnings: string[]): Options["form"][number] {
  const eq = v.indexOf("=");
  if (eq <= 0) throw new CurlError(`-F needs name=value, got ${decodeOr(v)}.`);
  const name = v.slice(0, eq);
  let rest = v.slice(eq + 1);
  if (rest.startsWith("@") || rest.startsWith("<")) throw new CurlError(`-F ${decodeOr(v)} reads a file; use --form-string name=value, or paste the body with --data-raw.`);
  const quoted = (s: string): [string, string] => {
    let out = "";
    let k = 1;
    for (; k < s.length && s[k] !== '"'; k++) out += s[k] === "\\" && k + 1 < s.length ? s[++k] : s[k];
    return [out, s.slice(k + 1)];
  };
  let value: string;
  if (rest.startsWith('"')) [value, rest] = quoted(rest);
  else {
    const semi = rest.indexOf(";");
    [value, rest] = semi < 0 ? [rest, ""] : [rest.slice(0, semi), rest.slice(semi)];
  }
  const part: Options["form"][number] = { name, value };
  while (rest.startsWith(";")) {
    rest = rest.slice(1);
    const m = /^([a-z]+)=/i.exec(rest);
    let param: string;
    if (m && rest[m[0].length] === '"') [param, rest] = quoted(rest.slice(m[0].length));
    else {
      const semi = rest.indexOf(";");
      param = (semi < 0 ? rest : rest.slice(0, semi)).slice(m?.[0].length ?? 0);
      rest = semi < 0 ? "" : rest.slice(semi);
    }
    const key = m?.[1].toLowerCase();
    if (key === "type" && CRLF.test(param)) throw new CurlError("An -F type holds a line break or NUL byte.");
    if (key === "type") part.type = param;
    else if (key === "filename") part.filename = param;
    else if (key === "headers" || key === "encoder") throw new CurlError(`-F ;${key}= isn't supported; paste the multipart body with --data-raw instead.`);
    else warnings.push(`Left out an unknown -F field: ${decodeOr(m ? m[0] + param : param)}.`);
  }
  return part;
}

// ---------- building the request ----------

/** Path with . and .. segments removed, as curl does unless --path-as-is. */
function removeDots(path: string): string {
  const q = path.search(/[?]/);
  const [p, query] = q < 0 ? [path, ""] : [path.slice(0, q), path.slice(q)];
  if (!/(^|\/)\.\.?(\/|$)/.test(p)) return path;
  const out: string[] = [];
  const segs = p.split("/");
  segs.forEach((s, n) => {
    const last = n === segs.length - 1;
    if (s === "..") {
      if (out.length > 1) out.pop();
      if (last) out.push("");
    } else if (s === ".") {
      if (last) out.push("");
    } else out.push(s);
  });
  return (out.join("/") || "/") + query;
}

/**
 * The URL curl requests for a URL it globs (without -g): a {a,b} set or a [1-3] or [a-c:2] range
 * stands for one request per value, \ quotes []{} (and anything inside a set), and an IPv6
 * address or [] stays as it is. A pattern with one value ({a}, [1-1]) is written out; one with
 * more is refused, as only one request is pasted at a time.
 */
function unglob(url: string): string {
  const bad = (): never => {
    throw new CurlError(`curl can't read the {…} or […] in ${decodeOr(url)} (URL globbing); add -g to send them as they are.`);
  };
  const many = (): never => {
    throw new CurlError("The URL uses curl's globbing ({a,b} or [1-3]), which makes several requests; paste one request at a time, or add -g to send the brackets as they are.");
  };
  let out = "";
  for (let i = 0; i < url.length; ) {
    const c = url[i];
    if (c === "\\" && /[[\]{}]/.test(url[i + 1] ?? "")) {
      out += url[i + 1];
      i += 2;
    } else if (c === "{") {
      const items: string[] = [];
      let cur = "";
      let k = i + 1;
      for (; ; k++) {
        const d = url[k];
        if (d === undefined || d === "{" || d === "[" || d === "]" || (d === "}" && k === i + 1)) bad();
        if (d === "}" || d === ",") {
          items.push(cur);
          cur = "";
          if (d === "}") break;
        } else if (d === "\\" && k + 1 < url.length) cur += url[++k];
        else cur += d;
      }
      if (items.length > 1) many();
      out += items[0];
      i = k + 1;
    } else if (c === "[") {
      const rest = url.slice(i);
      const literal = rest.startsWith("[]") ? "[]" : /^\[(?=[^\]]*:[^\]]*:)[0-9A-Fa-f:.]+(%[^\]]*)?\]/.exec(rest)?.[0];
      if (literal) {
        out += literal;
        i += literal.length;
        continue;
      }
      // [a-z] or [0-9], with an optional :step. curl pads numbers to a leading 0's width.
      // BigInt, as a Number would round a big one; curl refuses one above 2^63 - 2.
      const m = /^\[(?:([A-Za-z])-([^]))?(?:(\d+)-[ \t]*(\d+))?(?::(\d+))?\]/.exec(rest);
      if (!m || !(m[1] ?? m[3]) || (m[1] && m[3])) bad();
      const [lo, hi] = m![1] ? [BigInt(m![1].charCodeAt(0)), BigInt(m![2].charCodeAt(0))] : [BigInt(m![3]), BigInt(m![4])];
      const step = m![5] === undefined ? 1n : BigInt(m![5]);
      const max = 2n ** 63n - 2n;
      if (hi > max || step > max) bad();
      if (!step || (lo === hi && step !== 1n) || lo > hi || (lo < hi && step > hi - lo) || (m![1] && hi - lo > 25n)) bad();
      if (lo !== hi) many();
      out += m![1] ?? (m![3].startsWith("0") ? String(lo).padStart(m![3].length, "0") : String(lo));
      i += m![0].length;
    } else if (c === "}" || c === "]") bad();
    else {
      out += c;
      i++;
    }
  }
  return out;
}

const percentDecode = (s: string) => s.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

const basic = (credentials: string) => "Basic " + btoa(credentials);

/** Splits a URL like curl reads it (no scheme means http, or --proto-default). Byte strings in, byte strings out. */
function splitUrl(url: string, defaultScheme = "http") {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/(.*)$/s.exec(url);
  const scheme = (m ? m[1] : defaultScheme).toLowerCase();
  if (scheme !== "http" && scheme !== "https") throw new CurlError(`Only http and https URLs can be sent, not ${scheme}.`);
  const rest = m ? m[2] : url;
  const end = rest.search(/[/?#]/);
  let authority = end < 0 ? rest : rest.slice(0, end);
  let path = (end < 0 ? "" : rest.slice(end)).replace(/#.*$/s, "");
  if (!path.startsWith("/")) path = "/" + path;
  let userinfo: string | undefined;
  const at = authority.lastIndexOf("@");
  if (at >= 0) {
    userinfo = percentDecode(authority.slice(0, at));
    authority = authority.slice(at + 1);
  }
  const hm = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(authority);
  if (!hm || !hm[1]) throw new CurlError(`Can't read the host in ${decodeOr(url)}.`);
  const host = hm[1];
  if (/[\x00-\x20\x7f]/.test(host)) throw new CurlError(`Can't read the host in ${decodeOr(url)}.`);
  const port = hm[2] ? Number(hm[2]) : undefined;
  if (port !== undefined && !(port >= 1 && port <= 65535)) throw new CurlError(`Bad port in ${decodeOr(url)}.`);
  const explicit = port !== undefined && port !== (scheme === "https" ? 443 : 80) ? `:${port}` : "";
  return { scheme, host: host + explicit, userinfo, path };
}

const CRLF = /[\r\n\0]/;

/** Without HTTP whitespace at either end. (trim() would also strip 0xA0, a byte of UTF-8 text.) */
const trimHws = (s: string) => s.replace(/^[ \t]+|[ \t]+$/g, "");

/** An HTTP token (RFC 9110): a method or a header name. */
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** What curl reads as an empty header value: nothing but spaces and tabs (\v and \f are sent). */
const BLANK = /^[ \t]*$/;

/** Headers curl leaves out of an HTTP/2 request (connection-specific, RFC 9113 8.2.2). */
const H2_DROPPED = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"]);

/** Headers that carry credentials, which a copied command holds as they are. */
const CREDENTIALS = /^(authorization|proxy-authorization|cookie|x-api-key|api-key|x-auth-token)$/;

/**
 * A -H value in one of the three forms read exactly: "Name: value" (or "Name:value"), "Name:"
 * (removes curl's own header) and "Name;" (an empty header), with Name a token and nothing
 * between it and the separator. Returns the name and the line curl sends: "Name: value" as
 * written, spaces included, "Name;" as "Name:", and null for "Name:". curl reads other forms
 * by rules of its own ("Name ;", "Name;x: y", "Name : x"), so they are refused rather than guessed.
 */
function customHeader(h: string): [string, string | null] {
  const sep = h.search(/[:;]/);
  const name = sep < 0 ? "" : h.slice(0, sep);
  const rest = h.slice(sep + 1);
  if (TOKEN.test(name) && (h[sep] === ":" || rest === "")) {
    if (h[sep] === ";") return [name, `${name}:`];
    // With only spaces after the colon curl removes the header; otherwise it sends it as written.
    return [name, BLANK.test(rest) ? null : h];
  }
  throw new CurlError(
    `The header ${JSON.stringify(decodeOr(h))} can't be imported exactly: only "Name: value", "Name:" (no header) and "Name;" (empty) are read. Write it in one of those forms, and edit it in the tab after pasting if it must differ.`,
  );
}

/** Parses a cURL command line into a raw request for Replay. Throws CurlError with what's wrong. */
export function parseCurl(command: string): ParsedCurl {
  let src = command.replace(/\r\n?/g, "\n").trim();
  if (!src) throw new CurlError("Paste a curl command.");
  // Windows cmd as Chrome writes it (curl ^"…), or by hand: every line ends in ^ and nothing is
  // single-quoted. A POSIX command may hold ^" or a ^ at a line end inside its quotes.
  const lines = src.split("\n");
  const cmd = /^\S*curl(\.exe)?\s+\^"/i.test(src) || (lines.length > 1 && lines.slice(0, -1).every((l) => /\s\^$/.test(l)) && !src.includes("'"));
  // A body piped in with printf, as toCurl writes one that isn't plain text.
  let stdin: string | undefined;
  const pipe = cmd ? null : /^printf '([^']*)'[ \t]*\|[ \t]*/.exec(src);
  if (pipe) {
    stdin = printfBytes(utf8(pipe[1]));
    src = src.slice(pipe[0].length);
  }
  const words = cmd ? cmdWords(src) : posixWords(src);
  if (!words.length || !/(^|[/\\])curl(\.exe)?$/i.test(decodeOr(words[0]))) throw new CurlError("That isn't a curl command: it should start with curl.");
  const o = readOptions(words.slice(1), stdin);
  if (pipe && !o.flags.has("stdin")) throw new CurlError("curl doesn't read what printf pipes in; only --data-binary @- is read.");

  if (o.urls.length === 0) throw new CurlError("The command has no URL.");
  if (o.urls.length > 1) throw new CurlError("The command has more than one URL; paste one request at a time.");
  if (o.data.length && o.form.length) throw new CurlError("curl can't send -d and -F together.");
  const get = o.flags.has("get");
  if (get && o.form.length) throw new CurlError("curl can't send -F with -G.");
  const hasBody = !get && (o.data.length > 0 || o.form.length > 0);
  if (o.flags.has("head") && hasBody) throw new CurlError("curl can't send data with -I (HEAD); use -X HEAD.");

  const urlText = o.flags.has("globoff") ? o.urls[0] : unglob(o.urls[0]);
  const url = splitUrl(urlText, o.protoDefault);
  // curl refuses such a URL ("Malformed input"); --request-target sends one as is.
  if (/[\x00-\x20\x7f]/.test(urlText)) throw new CurlError("The URL holds a space or control character, which curl refuses; encode it (%20).");
  if (o.version === "HTTP/2" && o.h2Upgrade && url.scheme === "http") {
    o.version = "HTTP/1.1";
    o.warnings.push("curl --http2 only asks an http:// server to upgrade, so the request is sent over HTTP/1.1 (use --http2-prior-knowledge for HTTP/2).");
  }
  let path = o.flags.has("path-as-is") ? url.path : removeDots(url.path);
  const joined = o.data.map((d, n) => (n > 0 && !d.json ? "&" : "") + d.bytes).join("");
  const query = [...(get && o.data.length ? [joined] : []), ...o.urlQuery];
  if (query.length) {
    // The parts are joined with & and added once: after a & only when the URL's query (what
    // follows its first ?) has something in it and doesn't already end in &.
    const q = path.indexOf("?");
    path += (q < 0 ? "?" : q === path.length - 1 || path.endsWith("&") ? "" : "&") + query.join("&");
  }

  const method = o.method ?? (o.flags.has("head") ? "HEAD" : hasBody ? "POST" : "GET");
  if (!TOKEN.test(method)) throw new CurlError(`-X ${decodeOr(method)} isn't a valid method.`);
  const reqTarget = o.requestTarget ?? path;
  if (CRLF.test(reqTarget)) throw new CurlError("The URL holds a line break or NUL byte.");

  let body = "";
  let contentType: string | undefined;
  if (hasBody && o.form.length) {
    let boundary = "------------------------brainproxy";
    while (o.form.some((p) => (p.name + p.value + (p.filename ?? "") + (p.type ?? "")).includes(boundary))) boundary += "x";
    const esc = (s: string) => s.replace(/"/g, "%22").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    for (const p of o.form) {
      body += `--${boundary}\r\nContent-Disposition: form-data; name="${esc(p.name)}"${p.filename != null ? `; filename="${esc(p.filename)}"` : ""}\r\n`;
      if (p.type) body += `Content-Type: ${p.type}\r\n`;
      body += `\r\n${p.value}\r\n`;
    }
    body += `--${boundary}--\r\n`;
    contentType = `multipart/form-data; boundary=${boundary}`;
  } else if (hasBody) {
    body = joined;
    contentType = o.flags.has("json") ? "application/json" : "application/x-www-form-urlencoded";
  }

  // Custom headers, read before curl's own so the Authorization rule below can see them.
  const custom: [string, string | null][] = [];
  for (const h of o.headers) {
    if (h.startsWith(":")) {
      o.warnings.push(`Left out the HTTP/2 pseudo-header ${decodeOr(/^:[^:]*/.exec(h)![0])}.`);
      continue;
    }
    if (h.startsWith("@")) throw new CurlError(`-H ${decodeOr(h)} reads headers from a file; paste them instead.`);
    if (CRLF.test(h)) throw new CurlError(`The header ${JSON.stringify(decodeOr(h))} holds a line break or NUL byte.`);
    custom.push(customHeader(h));
  }

  // curl's own headers, in its order; a custom header of the same name replaces one.
  // A bearer token wins over -u, which wins over user:password in the URL: curl asks for Bearer
  // auth alone. With --basic too it waits for the server's challenge to pick one, unless a custom
  // Authorization header (or -H 'Authorization:', which removes it) stands in for both.
  const customAuth = custom.some(([n]) => n.toLowerCase() === "authorization");
  if (o.bearer != null && o.flags.has("basic") && !customAuth) throw new CurlError("--oauth2-bearer with --basic makes curl wait for the server's challenge before it sends either; keep one of them.");
  const defaults: [string, string][] = [["Host", url.host]];
  if (o.bearer != null) defaults.push(["Authorization", `Bearer ${o.bearer}`]);
  else if (o.user != null) defaults.push(["Authorization", basic(o.user)]);
  else if (url.userinfo != null) defaults.push(["Authorization", basic(url.userinfo.includes(":") ? url.userinfo : url.userinfo + ":")]);
  if (o.userAgent) defaults.push(["User-Agent", o.userAgent]);
  if (o.range) defaults.push(["Range", `bytes=${o.range}`]);
  if (o.referer) defaults.push(["Referer", o.referer]);
  defaults.push(["Accept", o.flags.has("json") ? "application/json" : "*/*"]);
  if (o.flags.has("compressed")) defaults.push(["Accept-Encoding", "deflate, gzip, br, zstd"]);
  if (o.cookies.length) defaults.push(["Cookie", o.cookies.join("; ")]);
  const trailing: [string, string][] = [];
  if (hasBody) trailing.push(["Content-Length", String(body.length)], ["Content-Type", contentType!]);

  // Each custom header drops curl's own of that name; "Name:" (a null value) sends nothing.
  // A custom Host goes first, where curl writes it. Which of several Host headers curl sends
  // depends on their order and forms, so more than one is refused rather than guessed.
  if (custom.filter(([n]) => n.toLowerCase() === "host").length > 1)
    throw new CurlError("The command sets Host more than once, which can't be imported exactly; keep one -H 'Host: …' and edit the request after pasting.");
  let customHost: string | undefined;
  const added: string[] = [];
  for (const [name, line] of custom) {
    const lower = name.toLowerCase();
    for (const list of [defaults, trailing]) {
      const k = list.findIndex(([n]) => n.toLowerCase() === lower);
      if (k >= 0) list.splice(k, 1);
    }
    if (line == null) continue;
    if (lower !== "host") added.push(line);
    else customHost ??= line;
  }

  const bad = [...defaults, ...trailing].find(([, v]) => CRLF.test(v));
  if (bad) throw new CurlError(`The ${decodeOr(bad[0])} header would hold a line break or NUL byte.`);
  const own = ([n, v]: [string, string]) => `${n}: ${v}`;
  const headers = [...(customHost ? [customHost] : []), ...defaults.map(own), ...added, ...trailing.map(own)];
  const head = [`${method} ${reqTarget} ${o.version}`, ...headers].join("\n");
  const bytes = `${head}\n\n${body}`;
  const text = decodeUtf8(bytes);
  const host = decodeOr(url.host);
  const target = `${url.scheme}://${host}`;
  return {
    raw: text ?? bytes,
    target,
    url: target + decodeOr(path),
    binary: text == null,
    warnings: o.warnings,
  };
}

// ---------- writing a command ----------

/**
 * Characters shown as they are inside '…': printable text and newlines, no control, line
 * separator or format characters (\p{Cf}: bidi controls, zero-width ones, the soft hyphen, the
 * invisible operators U+2060-2064, tag characters). A string, so no tool writes U+2028 out as a
 * raw line break in a regex literal.
 */
const PLAIN = new RegExp("^[^\\x00-\\x09\\x0b-\\x1f\\x7f-\\x9f\\u2028\\u2029\\p{Cf}]*$", "u");

/** Plain UTF-8 text, which goes in '…' as it is. */
const isPlainText = (bytes: string) => {
  const text = decodeUtf8(bytes);
  return text != null && PLAIN.test(text);
};

/**
 * One shell word holding exactly these bytes. Plain text goes in '…', with each ' and \ written
 * outside the quotes as \' and \\ (fish reads a \ inside '…' as an escape, POSIX shells don't);
 * control, bidi and non-UTF-8 bytes go in "$(printf '\NNN')". Nothing is expanded by sh, bash,
 * zsh or fish. NUL can't be passed at all.
 */
export function shellQuote(bytes: string): string {
  if (bytes.includes("\0")) throw new CurlError("A value holds a NUL byte, which a shell can't pass as an argument.");
  const text = decodeUtf8(bytes);
  let out = "";
  let run = "";
  let raw = "";
  const quoted = () => {
    if (run) out += `'${run}'`;
    run = "";
  };
  const printed = () => {
    if (raw) out += `"$(printf ${printfQuote(raw)})"`;
    raw = "";
  };
  // Not valid UTF-8: one char per byte, and only ASCII is shown as it is.
  for (const ch of text ?? bytes) {
    if ((text == null && ch.charCodeAt(0) > 0x7e) || !PLAIN.test(ch)) {
      quoted();
      raw += text == null ? ch : utf8(ch);
      continue;
    }
    printed();
    if (ch === "'" || ch === "\\") {
      quoted();
      out += "\\" + ch;
    } else run += ch;
  }
  quoted();
  printed();
  return out || "''";
}

/**
 * A printf format (single-quoted) that prints exactly these bytes, NUL included. Only printable
 * ASCII stands as it is; everything else, ' and \ too, is an octal escape, so no shell reads an
 * escape inside the quotes. A leading - is escaped too, or printf would read it as an option.
 */
function printfQuote(bytes: string): string {
  let out = "'";
  for (let k = 0; k < bytes.length; k++) {
    const ch = bytes[k];
    const c = ch.charCodeAt(0);
    if (ch === "%") out += "%%";
    else if (ch === "\n") out += "\\n";
    else if (c >= 0x20 && c < 0x7f && ch !== "'" && ch !== "\\" && !(k === 0 && ch === "-")) out += ch;
    else out += "\\" + c.toString(8).padStart(3, "0");
  }
  return out + "'";
}

/**
 * A raw request (as Replay holds it; `binary` when it is one char per byte) to `target`
 * (scheme://host[:port]) as a POSIX shell cURL command that sends the same request.
 * Throws CurlError when it can't be written; `warnings` says what may not work.
 */
export function toCurl(raw: string, target: string, binary = false): CurlCommand {
  const origin = utf8(target.trim().replace(/\/+$/, ""));
  const om = /^(https?):\/\/([^/?#\s]+)$/i.exec(origin);
  if (!om) throw new CurlError("Set a target (scheme://host[:port]) first.");
  const scheme = om[1].toLowerCase();
  const warnings: string[] = [];
  const all = latin1(textBytes(raw, binary));
  const { head, body } = splitRaw(all);
  if (body.length > CURL_MAX_BODY) throw new CurlError(`The body is ${body.length} bytes, too large to copy as a command; send it with the CLI (brainproxy send) instead.`);
  const lines = head.split(/\r?\n/);
  const rl = /^(\S+)[ \t]+(.+?)(?:[ \t]+(HTTP\/\S+))?[ \t]*$/i.exec(lines[0] ?? "");
  if (!rl) throw new CurlError("The request line isn't METHOD target HTTP/version.");
  const [, method, reqTarget, version = "HTTP/1.1"] = rl;
  const h2 = /^HTTP\/2/i.test(version);

  const args: string[] = [];
  let url: string;
  // curl would drop a #fragment or encode odd characters in a URL, so such a target goes as is.
  // So does an absolute URL: Send sends it to the target, and curl must connect there too.
  const asIs = /[#]|[^\x21-\x7e]/.test(reqTarget);
  if (reqTarget.startsWith("/") && !asIs) url = origin + reqTarget;
  else {
    url = origin + "/";
    args.push(`--request-target ${shellQuote(reqTarget)}`);
  }
  const authority = om[2].toLowerCase();
  const path = url.replace(/^https?:\/\/[^/?#]*/i, "").replace(/[?#].*$/s, "");
  if (/[[\]{}]/.test(url)) args.push("--globoff");
  if (/(^|\/)\.\.?(\/|$)/.test(path)) args.push("--path-as-is");
  if (h2) args.push(scheme === "http" ? "--http2-prior-knowledge" : "--http2");
  else if (/^HTTP\/1\.0$/i.test(version)) args.push("--http1.0");
  // Over https curl negotiates HTTP/2 when the server offers it.
  else if (scheme === "https") args.push("--http1.1");

  const hasLength = lines.some((l) => /^content-length\s*:/i.test(l));
  const hasData = body.length > 0 || hasLength;
  if (method === "HEAD" && !hasData) args.push("--head");
  else if (method !== (hasData ? "POST" : "GET")) args.push(`-X ${shellQuote(method)}`);

  // curl knows a header by the name right before its colon and sends a -H line as written, so
  // each line is copied as it is, spaces included. With spaces before the colon
  // ("Transfer-Encoding : chunked", a smuggling probe) it is none of curl's own headers.
  const parsed: { name: string; lower: string; value: string; line: string; spaced: boolean; blank: boolean }[] = [];
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon <= 0 || /^[ \t]/.test(line)) {
      warnings.push(`Left out a line that isn't a header: ${decodeOr(line).slice(0, 60)}`);
      continue;
    }
    const name = line.slice(0, colon).replace(/[ \t]+$/, "");
    // Only a token name goes in a -H that curl reads as written (curl reads -H @NAME as a
    // file of headers).
    if (!TOKEN.test(name)) {
      warnings.push(`Left out a header whose name isn't a valid token (curl may read it otherwise, or as a file): ${decodeOr(name).slice(0, 60)}`);
      continue;
    }
    const rest = line.slice(colon + 1);
    parsed.push({ name, lower: name.toLowerCase(), value: trimHws(rest), line, spaced: name.length < colon, blank: BLANK.test(rest) });
  }
  const named = (lower: string) => parsed.filter((h) => !h.spaced && h.lower === lower);
  const hosts = named("host");
  const lengths = named("content-length");
  // curl reads only the first Transfer-Encoding, and chunks the body when one of its
  // comma-separated codings is chunked (not over HTTP/2).
  const te = named("transfer-encoding")[0]?.value ?? "";
  const chunked = !h2 && te.split(",").some((c) => trimHws(c).toLowerCase() === "chunked");

  const seen = new Set<string>();
  const spaced: string[] = [];
  const blanked: string[] = [];
  for (const h of parsed) {
    if (!h.spaced) {
      seen.add(h.lower);
      // curl writes these itself: the length from the body, Host from the URL unless it differs.
      if (h.lower === "content-length") continue;
      if (h.lower === "host" && hosts.length === 1 && h.value.toLowerCase() === authority) continue;
    }
    if (!h.blank) {
      if (h.spaced) spaced.push(h.name);
      args.push(`-H ${shellQuote(h.line)}`);
      continue;
    }
    // "Name:" with nothing after it removes curl's header; "Name;" sends it empty, as "Name:".
    args.push(`-H ${shellQuote(`${h.name};`)}`);
    if (h.line !== `${h.name}:`) blanked.push(h.name);
  }
  // Headers curl would add that the request doesn't have. (Over HTTP/2 both use the target's
  // authority when there's no Host.)
  if (!seen.has("host") && !h2) args.push("-H 'Host:'");
  if (!seen.has("user-agent")) args.push("-H 'User-Agent:'");
  if (!seen.has("accept")) args.push("-H 'Accept:'");
  if (hasData && !seen.has("content-type")) args.push("-H 'Content-Type:'");
  if (body.length > 1024 && !seen.has("expect")) args.push("-H 'Expect:'");
  // curl adds a Content-Length unless it chunks the body. A request with a Transfer-Encoding
  // or a spaced Content-Length and no Content-Length of its own goes without one, as written.
  if (hasData && !lengths.length && !chunked && parsed.some((h) => h.lower === "transfer-encoding" || h.lower === "content-length")) args.push("-H 'Content-Length:'");

  if (hosts.length > 1) warnings.push(`The request has ${hosts.length} Host headers and curl sends only the first (${decodeOr(hosts[0].value).slice(0, 60)}), so the command sends a different request.`);
  if (chunked) warnings.push(`curl chunks the body itself with Transfer-Encoding: chunked, so a body already chunked is chunked twice${lengths.length ? ", and it sends no Content-Length" : ""}.`);
  else if (lengths.length > 1 || (lengths.length && lengths[0].value !== String(body.length)))
    warnings.push(`curl sends Content-Length: ${body.length}, the body's length, in place of the request's ${lengths.map((h) => decodeOr(h.value).slice(0, 20)).join(", ")}.`);
  if (spaced.length)
    warnings.push(`Copied as written with a space before the colon: ${spaced.map(decodeOr).join(", ")}. curl sends such a header as it is over HTTP/1, but pasting the command back into brainproxy is refused; edit the header in the tab instead.`);
  if (blanked.length) warnings.push(`curl sends an empty header only as "Name:", so ${blanked.map(decodeOr).join(", ")} lose${blanked.length > 1 ? "" : "s"} the spaces around the colon.`);
  if (h2) {
    // Not allowed in HTTP/2: curl leaves them out, and keeps TE only as "trailers", when it
    // names that coding.
    const codings = (v: string) => v.split(",").map((c) => trimHws(c).toLowerCase());
    const te = parsed.filter((h) => !h.spaced && h.lower === "te");
    const hop = parsed.filter((h) => !h.spaced && (H2_DROPPED.has(h.lower) || (h.lower === "te" && !codings(h.value).includes("trailers"))));
    if (hop.length) warnings.push(`Over HTTP/2 curl leaves out ${[...new Set(hop.map((h) => decodeOr(h.name)))].join(", ")}, which HTTP/2 doesn't allow.`);
    if (te.some((h) => codings(h.value).includes("trailers") && h.value !== "trailers")) warnings.push('Over HTTP/2 curl sends TE as "trailers" alone.');
  }
  const secrets = new Map(parsed.filter((h) => CREDENTIALS.test(h.lower)).reverse().map((h) => [h.lower, decodeOr(h.name)]));
  if (secrets.size) warnings.push(`The command carries the request's credentials as they are (${[...secrets.values()].reverse().join(", ")}); keep it where you would keep them.`);

  let pipe = "";
  if (hasData) {
    // --data-raw never reads a file, even for a body starting with @. A body that isn't plain
    // text (NUL, control bytes, not UTF-8) goes in through printf instead.
    if (isPlainText(body)) args.push(`--data-raw ${shellQuote(body)}`);
    else {
      pipe = `printf ${printfQuote(body)} | `;
      args.push("--data-binary @-");
    }
  }
  const command = pipe + [`curl ${shellQuote(url)}`, ...args].join(" \\\n  ");
  // printf is built into the shell, so only --data-raw meets the limit on one argument.
  if (!pipe && body.length > CURL_ARG_WARN) warnings.push(`The body is ${body.length} bytes: a shell may refuse an argument over 128 KB. Save the body to a file and use --data-binary @FILE instead.`);
  return { command, warnings };
}
