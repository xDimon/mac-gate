//! Sources of the lists: files beside the settings, read again when they
//! change, and URLs, fetched once a day into a cache the lists are built
//! from. A fetch that fails or brings no entries leaves the last good copy
//! in place, and is tried again in an hour.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use tokio::task::JoinHandle;

use crate::command;
use crate::config::{Settings, Source};
use crate::lists::Lists;
use crate::pf::write_private;
use crate::resolver::Journal;

pub const EVERY: Duration = Duration::from_hours(24);
const RETRY: Duration = Duration::from_hours(1);
const FETCH_LIMIT: Duration = Duration::from_mins(1);
const MAX_BYTES: &str = "20000000";
const CURL: &str = "/usr/bin/curl";
/// The owner asks for a fetch now; next to the state file.
pub const UPDATE_FLAG: &str = "update";
/// The cached copies of the URLs, next to the state file.
pub const CACHE: &str = "sources";

/// The cached copy of a URL: named by a hash of it, so that a changed URL
/// never reads the copy of the old one.
pub fn cache_file(dir: &Path, url: &str) -> PathBuf {
    dir.join(format!("{:016x}.lst", fnv1a(url)))
}

fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The entries of a source, or why it is refused: none at all, or more
/// lines that are no entry than entries — a page of something else.
pub fn check(text: &str) -> Result<usize, String> {
    let mut l = Lists::default();
    l.add("check", text);
    let n = l.entry_count();
    if n == 0 {
        return Err("no entries".to_owned());
    }
    if l.rejected.len() > n {
        return Err(format!(
            "{} lines that are no entry against {n} entries",
            l.rejected.len()
        ));
    }
    Ok(n)
}

/// An HTTP error, a redirect loop or an oversize body fails; the body of
/// an error page never passes for the list.
pub async fn fetch(url: &str, iface: Option<&str>) -> io::Result<String> {
    let secs = FETCH_LIMIT.as_secs().to_string();
    let mut args = vec![
        "-f",
        "-s",
        "-S",
        "-L",
        "--max-redirs",
        "5",
        "--proto",
        "=http,https",
        "--max-time",
        &secs,
        "--max-filesize",
        MAX_BYTES,
    ];
    if let Some(i) = iface {
        args.extend(["--interface", i]);
    }
    args.push(url);
    command::run(CURL, &args, None, FETCH_LIMIT + Duration::from_secs(5)).await
}

/// Through the tunnel when there is one, else or failing that, directly.
/// The text and the way it came.
pub async fn fetch_any(url: &str, tunnel: Option<&str>) -> Result<(String, &'static str), String> {
    let mut tried = String::new();
    if let Some(t) = tunnel {
        match fetch(url, Some(t)).await {
            Ok(text) => return Ok((text, "tunnel")),
            Err(e) => tried = format!("tunnel: {e}; "),
        }
    }
    fetch(url, None)
        .await
        .map(|text| (text, "direct"))
        .map_err(|e| format!("{tried}direct: {e}"))
}

pub fn write_cache(path: &Path, text: &str) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    write_private(&tmp, text)?;
    fs::rename(&tmp, path)
}

/// The lists from the files and the cached copies, in the order of the
/// settings. A source that cannot be read is missing, and named.
pub fn build(settings: &Settings, base: &Path, cache: &Path) -> (Lists, Vec<String>) {
    let mut lists = Lists::default();
    let mut missing = Vec::new();
    for list in &settings.lists {
        for source in &list.sources {
            let path = match source {
                Source::File(p) => base.join(p),
                Source::Url(u) => cache_file(cache, u),
            };
            match fs::read_to_string(&path) {
                Ok(text) => lists.add(&list.name, &text),
                Err(e) => missing.push(format!("{} {source}: {e}", list.name)),
            }
        }
    }
    (lists, missing)
}

fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// How long until a copy fetched at `fetched` is due again; now without one.
fn due_in(fetched: Option<SystemTime>, now: SystemTime) -> Duration {
    fetched
        .and_then(|t| (t + EVERY).duration_since(now).ok())
        .unwrap_or_default()
}

type Fetched = Vec<(String, Result<(String, &'static str), String>)>;

/// Keeps the lists current: looks at the files every step, fetches the
/// URLs when due, in a task of its own so that the watch never waits on it.
pub struct Updater {
    pub settings: Settings,
    base: PathBuf,
    cache: PathBuf,
    flag: PathBuf,
    /// The file sources and their modification times as last read.
    stamps: Vec<(PathBuf, Option<SystemTime>)>,
    due: HashMap<String, Instant>,
    task: Option<JoinHandle<Fetched>>,
}

impl Updater {
    /// A URL is due a day after its cached copy was written: the copy's
    /// time says when, across restarts.
    pub fn new(settings: Settings, base: &Path, cache: &Path, flag: PathBuf) -> Self {
        let (now, wall) = (Instant::now(), SystemTime::now());
        let due = settings
            .urls()
            .map(|u| {
                let at = now + due_in(modified(&cache_file(cache, u)), wall);
                (u.to_owned(), at)
            })
            .collect();
        let stamps = settings
            .files()
            .map(|p| {
                let path = base.join(p);
                let t = modified(&path);
                (path, t)
            })
            .collect();
        Self {
            settings,
            base: base.to_owned(),
            cache: cache.to_owned(),
            flag,
            stamps,
            due,
            task: None,
        }
    }

    pub fn build(&self) -> (Lists, Vec<String>) {
        build(&self.settings, &self.base, &self.cache)
    }

    /// One step: takes in a finished fetch, looks at the files, starts the
    /// fetch of what is due. True when a source changed.
    pub async fn poll(&mut self, tunnel: Option<String>, journal: &Journal) -> bool {
        let now = Instant::now();
        if self.flag.exists() {
            let _ = fs::remove_file(&self.flag);
            journal.log(format_args!("sources update requested"));
            for at in self.due.values_mut() {
                *at = now;
            }
        }
        let mut changed = false;
        if self.task.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(task) = self.task.take()
        {
            match task.await {
                Ok(fetched) => changed |= self.take_in(fetched, journal),
                Err(e) => journal.log(format_args!("sources-fail task: {e}")),
            }
        }
        for (path, stamp) in &mut self.stamps {
            let t = modified(path);
            if t != *stamp {
                *stamp = t;
                changed = true;
                journal.log(format_args!("source {} changed", path.display()));
            }
        }
        if self.task.is_none() {
            let due: Vec<String> = self
                .due
                .iter()
                .filter(|&(_, &at)| at <= now)
                .map(|(u, _)| u.clone())
                .collect();
            if !due.is_empty() {
                for u in &due {
                    // Set again by the result.
                    self.due.insert(u.clone(), now + RETRY);
                }
                self.task = Some(tokio::spawn(async move {
                    let mut out = Vec::new();
                    for u in due {
                        let got = fetch_any(&u, tunnel.as_deref()).await;
                        out.push((u, got));
                    }
                    out
                }));
            }
        }
        changed
    }

    fn take_in(&mut self, fetched: Fetched, journal: &Journal) -> bool {
        let now = Instant::now();
        let mut changed = false;
        for (url, got) in fetched {
            let checked = got.and_then(|(text, via)| check(&text).map(|n| (text, via, n)));
            let (text, via, n) = match checked {
                Ok(v) => v,
                Err(e) => {
                    journal.log(format_args!("source-fail {url}: {e}"));
                    self.due.insert(url, now + RETRY);
                    continue;
                }
            };
            let path = cache_file(&self.cache, &url);
            let new = fs::read_to_string(&path).ok().as_deref() != Some(text.as_str());
            // Written even when the same: its time says when it was fetched.
            if let Err(e) = write_cache(&path, &text) {
                journal.log(format_args!("source-fail {url}: cache: {e}"));
                self.due.insert(url, now + RETRY);
                continue;
            }
            journal.log(format_args!(
                "source {url} via={via} entries={n} changed={new}"
            ));
            changed |= new;
            self.due.insert(url, now + EVERY);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    #[test]
    fn cache_name_is_stable_and_per_url() {
        let d = Path::new("/c");
        assert_eq!(cache_file(d, "a"), cache_file(d, "a"));
        assert_ne!(cache_file(d, "a"), cache_file(d, "b"));
        // FNV-1a of the empty string is its offset basis.
        assert_eq!(cache_file(d, ""), PathBuf::from("/c/cbf29ce484222325.lst"));
    }

    #[test]
    fn refuses_what_is_no_list() {
        assert!(check("404: Not Found").is_err());
        assert!(check("").is_err());
        assert!(check("<html>\n<body>\nnothing here\n</body>\n</html>\nx.org\n").is_err());
        assert_eq!(check("telegram.org\n149.154.160.0/20\n"), Ok(2));
        assert_eq!(check("# c\n.test\n"), Ok(1));
    }

    #[test]
    fn due_a_day_after_the_copy() {
        let now = SystemTime::now();
        assert_eq!(due_in(None, now), Duration::ZERO);
        assert_eq!(due_in(Some(now - EVERY * 2), now), Duration::ZERO);
        assert_eq!(
            due_in(Some(now - Duration::from_hours(1)), now),
            Duration::from_hours(23)
        );
    }

    #[test]
    fn builds_from_files_and_copies_and_names_the_missing() {
        let dir = std::env::temp_dir().join(format!("mac-gate-src-{}", std::process::id()));
        let cache = dir.join("cache");
        fs::create_dir_all(dir.join("lists")).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::write(dir.join("lists/custom.lst"), "example.com\n").unwrap();
        let s = parse(
            "[[list]]\nname = \"custom\"\nsources = [\"lists/custom.lst\"]\n\
             [[list]]\nname = \"telegram\"\nsources = [\"https://h/a.lst\", \"https://h/b.lst\"]\n\
             [[tunnel]]\nname = \"t\"\nconf = \"t.conf\"\n\
             [[rule]]\nname = \"r\"\nwhen = \"always\"\nlists = [\"custom\", \"telegram\"]\ntunnels = [\"t\"]\n",
        )
        .unwrap();
        write_cache(&cache_file(&cache, "https://h/a.lst"), "telegram.org\n").unwrap();
        let (lists, missing) = build(&s, &dir, &cache);
        assert_eq!(lists.match_domain("x.example.com"), ["custom"]);
        assert_eq!(lists.match_domain("telegram.org"), ["telegram"]);
        assert_eq!(missing.len(), 1);
        assert!(missing[0].starts_with("telegram https://h/b.lst: "));
        fs::remove_dir_all(&dir).unwrap();
    }
}
