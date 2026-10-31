//! `browser list|open`: start a locally installed browser that goes through this project's
//! proxy, in its own profile next to the project file, so the user's normal browser,
//! sessions, and settings are untouched.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use brainproxy_core::store::Store;
use brainproxy_core::Error;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::output::Out;

#[derive(Subcommand)]
pub enum BrowserCmd {
    /// Browsers found on this machine (Chromium-based and Firefox).
    List,
    /// Start a browser through the running proxy, in a separate profile for this project.
    #[command(after_help = "Chromium-based browsers trust the brainproxy CA in that profile only \
        (--ignore-certificate-errors-spki-list with the CA key; other certificate errors still show). Firefox gets \
        the proxy settings; import the CA once in that profile (the output says how). Loopback addresses go through \
        the proxy too. Profiles live next to the project file (<project>.browsers/<id>) and keep their cookies.")]
    Open {
        /// Browser id from `browser list` (default: the first one found, Chromium-based first).
        #[arg(long)]
        browser: Option<String>,
        /// Page to open: an http(s) URL or about:blank.
        url: Option<String>,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Chromium,
    Firefox,
}

pub(crate) struct Found {
    id: &'static str,
    name: &'static str,
    kind: Kind,
    path: PathBuf,
}

/// (id, name, kind, macOS app executable, Linux executables on PATH, Windows executable
/// under Program Files or %LOCALAPPDATA%)
type Known = (&'static str, &'static str, Kind, &'static str, &'static [&'static str], &'static str);
const KNOWN: &[Known] = &[
    (
        "chrome",
        "Google Chrome",
        Kind::Chromium,
        "Google Chrome.app/Contents/MacOS/Google Chrome",
        &["google-chrome", "google-chrome-stable"],
        r"Google\Chrome\Application\chrome.exe",
    ),
    (
        "chromium",
        "Chromium",
        Kind::Chromium,
        "Chromium.app/Contents/MacOS/Chromium",
        &["chromium", "chromium-browser"],
        r"Chromium\Application\chrome.exe",
    ),
    (
        "edge",
        "Microsoft Edge",
        Kind::Chromium,
        "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        &["microsoft-edge", "microsoft-edge-stable"],
        r"Microsoft\Edge\Application\msedge.exe",
    ),
    (
        "brave",
        "Brave",
        Kind::Chromium,
        "Brave Browser.app/Contents/MacOS/Brave Browser",
        &["brave-browser", "brave"],
        r"BraveSoftware\Brave-Browser\Application\brave.exe",
    ),
    (
        "firefox",
        "Firefox",
        Kind::Firefox,
        "Firefox.app/Contents/MacOS/firefox",
        &["firefox", "firefox-esr"],
        r"Mozilla Firefox\firefox.exe",
    ),
];

pub(crate) fn find() -> Vec<Found> {
    let mut app_dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = std::env::var_os("HOME") {
        app_dirs.push(PathBuf::from(home).join("Applications"));
    }
    let path_dirs: Vec<PathBuf> =
        std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    let win_dirs: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
        .iter()
        .filter(|_| cfg!(windows))
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect();
    KNOWN
        .iter()
        .filter_map(|&(id, name, kind, mac, linux, win)| {
            let mac = app_dirs.iter().map(|d| d.join(mac));
            let linux = linux.iter().flat_map(|exe| path_dirs.iter().map(move |d| d.join(exe)));
            let win = win_dirs.iter().map(|d| d.join(win));
            let path = mac.chain(linux).chain(win).find(|p| p.is_file())?;
            Some(Found { id, name, kind, path })
        })
        .collect()
}

/// Whether `crawl --browser` can run on this platform (it passes pipes the Unix way).
const BROWSER_CRAWL: bool = cfg!(unix);

/// The Chromium-family browser for a browser crawl: `id` from `browser list`, or the
/// first one found. The crawl drives it over the DevTools protocol, which Firefox lacks.
pub(crate) fn chromium(id: Option<&str>) -> Result<PathBuf, Error> {
    if !BROWSER_CRAWL {
        return Err(Error::InvalidInput(
            "the browser crawl (--browser) runs on Linux and macOS; on Windows, browse the site through the proxy \
             (brainproxy browser open)"
                .into(),
        ));
    }
    let found = find();
    let chromium: Vec<&Found> = found.iter().filter(|f| f.kind == Kind::Chromium).collect();
    match id {
        Some(id) => match found.iter().find(|f| f.id == id) {
            Some(f) if f.kind == Kind::Chromium => Ok(f.path.clone()),
            Some(f) => Err(Error::InvalidInput(format!(
                "the browser crawl drives Chromium-based browsers (Chrome, Chromium, Edge, Brave), not {}",
                f.name
            ))),
            None => Err(Error::NotFound(format!(
                "browser {id:?}; Chromium-based browsers found: {}",
                if chromium.is_empty() {
                    "none".into()
                } else {
                    chromium.iter().map(|f| f.id).collect::<Vec<_>>().join(", ")
                }
            ))),
        },
        None => chromium.first().map(|f| f.path.clone()).ok_or_else(|| {
            Error::NotFound(
                "no Chromium-based browser found for --browser (Chrome, Chromium, Edge or Brave on the PATH or in the \
                 usual install folders; on Kali: sudo apt install chromium). See `brainproxy browser list`."
                    .into(),
            )
        }),
    }
}

fn describe(f: &Found) -> Value {
    json!({"id": f.id, "name": f.name, "kind": if f.kind == Kind::Chromium { "chromium" } else { "firefox" }, "path": f.path})
}

pub fn browser(project: &Path, home: &Path, cmd: BrowserCmd, out: &Out) -> Result<(), Error> {
    let found = find();
    match cmd {
        BrowserCmd::List => {
            let list: Vec<Value> = found.iter().map(describe).collect();
            let data =
                json!({"browsers": list, "default": found.first().map(|f| f.id), "browser_crawl": BROWSER_CRAWL});
            out.ok(data, || {
                if found.is_empty() {
                    return "no supported browser found (Chrome, Chromium, Edge, Brave, Firefox)".into();
                }
                found
                    .iter()
                    .map(|f| format!("{:<9} {}  {}", f.id, f.name, f.path.display()))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            Ok(())
        }
        BrowserCmd::Open { browser, url } => {
            let (data, text) = open(project, home, &found, browser, url.unwrap_or_else(|| "about:blank".into()), None)?;
            out.ok(data, || text);
            Ok(())
        }
    }
}

/// Starts a browser through the running proxy at `page`; `fresh` names a separate
/// profile that starts empty (`auth record`). Returns the output data and a summary.
pub(crate) fn open(
    project: &Path,
    home: &Path,
    found: &[Found],
    browser: Option<String>,
    page: String,
    fresh: Option<&str>,
) -> Result<(Value, String), Error> {
    check_url(&page)?;
    let b = match &browser {
        Some(id) => found.iter().find(|f| f.id == id).ok_or_else(|| {
            let ids: Vec<&str> = found.iter().map(|f| f.id).collect();
            Error::NotFound(format!(
                "browser {id:?}; found: {}",
                if ids.is_empty() { "none".into() } else { ids.join(", ") }
            ))
        })?,
        None => found.first().ok_or_else(|| {
            Error::NotFound("no supported browser found (Chrome, Chromium, Edge, Brave, Firefox)".into())
        })?,
    };
    let store = Store::open(project)?;
    let state = crate::proxy_cmd::running_here(&store)?.ok_or_else(|| {
        Error::Conflict("the proxy isn't running for this project; start it with `brainproxy proxy start`".into())
    })?;
    // A wildcard listen address isn't something to connect to.
    let proxy = state.listen.replace("0.0.0.0:", "127.0.0.1:").replace("[::]:", "[::1]:");
    let (port, host) = proxy.rsplit_once(':').map(|(h, p)| (p.to_string(), h.to_string())).unwrap_or_default();
    let profile = match fresh {
        // A throwaway profile, emptied first: no earlier session can skip the login.
        Some(tag) => {
            let dir = profile_dir(project, &format!("{}-{tag}", b.id));
            let _ = std::fs::remove_dir_all(&dir);
            dir
        }
        None => profile_dir(project, b.id),
    };
    std::fs::create_dir_all(&profile)?;
    let mut cmd = Command::new(&b.path);
    let mut note = Value::Null;
    match b.kind {
        Kind::Chromium => {
            let (ca, _) = crate::proxy_cmd::load_ca(home)?;
            cmd.arg(format!("--user-data-dir={}", profile.display()))
                .arg(format!("--proxy-server=http://{proxy}"))
                // Chromium bypasses the proxy for loopback unless told otherwise.
                .arg("--proxy-bypass-list=<-loopback>")
                .arg(format!("--ignore-certificate-errors-spki-list={}", ca.spki_sha256_base64()))
                // Keep the browser's own background traffic out of the history.
                .args(["--no-first-run", "--no-default-browser-check", "--disable-background-networking"])
                .args(["--disable-component-update", "--disable-sync", "--disable-domain-reliability"])
                .args(["--disable-client-side-phishing-detection", "--disable-default-apps", "--no-pings"])
                .arg("--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication")
                // Everything after `--` is a URL to Chromium, never a switch.
                .arg("--")
                .arg(&page);
        }
        Kind::Firefox => {
            std::fs::write(profile.join("user.js"), firefox_prefs(&host, &port))?;
            cmd.arg("-profile").arg(&profile).args(["-no-remote", "-new-instance"]).arg(&page);
            note = json!(format!(
                "Firefox doesn't take the CA from the command line. Once per profile: Settings > Privacy & Security > \
                 Certificates > View Certificates > Authorities > Import {}, and tick \"Trust this CA to identify websites\".",
                state.ca_cert.display()
            ));
        }
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    // It outlives this command and isn't hit by our signals.
    crate::process::detach(&mut cmd);
    let child = cmd.spawn().map_err(|e| Error::InvalidInput(format!("can't start {}: {e}", b.name)))?;
    let data = json!({
        "browser": describe(b),
        "pid": child.id(),
        "proxy": format!("http://{proxy}"),
        "profile": profile,
        "url": page,
        "note": note,
    });
    let text = format!("{} started through the proxy at http://{proxy}", b.name);
    Ok((data, text))
}

/// Only http(s) URLs and about:blank: anything else (`--renderer-cmd-prefix=...`,
/// `-profile`, `file:`, `javascript:`) could be read as a launch switch or open local files.
fn check_url(url: &str) -> Result<(), Error> {
    let lower = url.to_ascii_lowercase();
    let web = (lower.starts_with("http://") || lower.starts_with("https://")) && url.len() > "https://".len();
    if (web || lower == "about:blank") && !url.starts_with('-') && !url.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!("can only open http(s) URLs or about:blank, not {url:?}")))
    }
}

/// `<project>.browsers/<id>`: one profile per browser per project.
fn profile_dir(project: &Path, id: &str) -> PathBuf {
    let mut name = project.file_name().unwrap_or_default().to_os_string();
    name.push(".browsers");
    project.with_file_name(name).join(id)
}

/// Firefox prefs: everything through the proxy (loopback included), and the browser's own
/// background requests off so they don't fill the history.
fn firefox_prefs(host: &str, port: &str) -> String {
    let port: u16 = port.parse().unwrap_or(8080);
    let mut prefs: Vec<(String, String)> = vec![
        ("network.proxy.type".into(), "1".into()),
        ("network.proxy.http".into(), format!("{host:?}")),
        ("network.proxy.http_port".into(), port.to_string()),
        ("network.proxy.ssl".into(), format!("{host:?}")),
        ("network.proxy.ssl_port".into(), port.to_string()),
        ("network.proxy.share_proxy_settings".into(), "true".into()),
        ("network.proxy.no_proxies_on".into(), "\"\"".into()),
        ("network.proxy.allow_hijacking_localhost".into(), "true".into()),
    ];
    for off in [
        "browser.shell.checkDefaultBrowser",
        "app.update.auto",
        "network.captive-portal-service.enabled",
        "network.connectivity-service.enabled",
        "browser.safebrowsing.malware.enabled",
        "browser.safebrowsing.phishing.enabled",
        "datareporting.healthreport.uploadEnabled",
        "datareporting.policy.dataSubmissionEnabled",
        "toolkit.telemetry.enabled",
        "browser.newtabpage.activity-stream.feeds.topsites",
        "extensions.getAddons.cache.enabled",
    ] {
        prefs.push((off.into(), "false".into()));
    }
    prefs.iter().map(|(k, v)| format!("user_pref(\"{k}\", {v});\n")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_next_to_project() {
        assert_eq!(profile_dir(Path::new("/w/acme.bpdb"), "chrome"), Path::new("/w/acme.bpdb.browsers/chrome"));
    }

    #[test]
    fn only_web_urls_are_opened() {
        for ok in ["https://app.test/", "HTTP://a.test:8080/x?y=1", "about:blank"] {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "--renderer-cmd-prefix=/usr/bin/touch /tmp/pwned",
            "-profile",
            "--user-data-dir=/home/u/.config/chromium",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "http://",
            "https://a.test/\n--x",
            "",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn firefox_prefs_point_at_the_proxy() {
        let p = firefox_prefs("127.0.0.1", "18080");
        assert!(p.contains("user_pref(\"network.proxy.http\", \"127.0.0.1\");"));
        assert!(p.contains("user_pref(\"network.proxy.ssl_port\", 18080);"));
        assert!(p.contains("user_pref(\"network.proxy.allow_hijacking_localhost\", true);"));
    }
}
