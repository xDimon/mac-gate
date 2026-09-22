//! Sources of the lists: files beside the settings, read again when they
//! change, and URLs, fetched once a day into a cache the lists are built
//! from. A fetch that fails or brings no entries leaves the last good copy
//! in place, and is tried again in an hour. Every source is kept as a copy,
//! files included: a source that stops reading falls back on its copy
//! instead of leaving the list short.

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

/// Whether a file reads as a list at all, and how many entries it holds or
/// why it could not be read: for the journal, where a changed file says
/// what it now brings, and for the step, which waits out what is no list.
fn entries_of(path: &Path) -> (bool, String) {
    match fs::read_to_string(path) {
        Ok(text) => match check(&text) {
            Ok(n) => (true, format!("entries={n}")),
            Err(e) => (false, format!("no list: {e}")),
        },
        Err(e) => (false, format!("unreadable: {e}")),
    }
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

/// What a build of the lists found.
#[derive(Debug, Default)]
pub struct Built {
    pub lists: Lists,
    /// Sources with neither a readable file nor a copy, as "list source: why".
    pub missing: Vec<String>,
    /// File sources taken from their copy, the file itself unreadable.
    pub stale: Vec<String>,
}

/// The copy of a file source is named by the path the settings write, so
/// that a renamed file never reads the copy of the old one. The prefix
/// keeps it apart from the copy of a URL.
fn file_key(rel: &Path) -> String {
    format!("file:{}", rel.display())
}

/// A file source: read beside the settings and kept as a copy, else taken
/// from the last copy. A copy is written only when the text is a list, so
/// that a truncated read never replaces a good one; a file that reads and
/// holds nothing is taken as it is — emptying a list is the owner's to do.
fn read_file(rel: &Path, base: &Path, cache: &Path) -> Result<(String, bool), String> {
    let copy = cache_file(cache, &file_key(rel));
    match fs::read_to_string(base.join(rel)) {
        Ok(text) => {
            if check(&text).is_ok() {
                let _ = write_cache(&copy, &text);
            }
            Ok((text, false))
        }
        Err(e) => match fs::read_to_string(&copy) {
            Ok(text) => Ok((text, true)),
            Err(_) => Err(e.to_string()),
        },
    }
}

/// The lists from the files and the cached copies, in the order of the
/// settings. A source with neither a file nor a copy is missing, and named.
pub fn build(settings: &Settings, base: &Path, cache: &Path) -> Built {
    let mut out = Built::default();
    for list in &settings.lists {
        for source in &list.sources {
            let got = match source {
                Source::File(p) => read_file(p, base, cache),
                Source::Url(u) => fs::read_to_string(cache_file(cache, u))
                    .map(|text| (text, false))
                    .map_err(|e| e.to_string()),
            };
            match got {
                Ok((text, from_copy)) => {
                    if from_copy {
                        out.stale.push(format!("{} {source}", list.name));
                    }
                    out.lists.add(&list.name, &text);
                }
                Err(e) => out.missing.push(format!("{} {source}: {e}", list.name)),
            }
        }
    }
    out
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

/// A file source and the modification times that decide when it is read:
/// `taken` as of the last read, `seen` as of the last step.
struct Stamp {
    path: PathBuf,
    taken: Option<SystemTime>,
    seen: Option<SystemTime>,
}

/// Keeps the lists current: looks at the files every step, fetches the
/// URLs when due, in a task of its own so that the watch never waits on it.
pub struct Updater {
    pub settings: Settings,
    base: PathBuf,
    cache: PathBuf,
    flag: PathBuf,
    /// The file sources and the times that decide when they are read.
    stamps: Vec<Stamp>,
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
                Stamp {
                    path,
                    taken: t,
                    seen: t,
                }
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

    pub fn build(&self) -> Built {
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
        changed |= self.follow_files(journal);
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

    /// Looks at the file sources. A change is taken in only once the
    /// modification time has held still for a step, or the file reads as a
    /// list straight away: an editor that truncates in place leaves the file
    /// holding nothing for a moment, and reading it there drops the entries
    /// of that source and the routes of its subnets until the next step. A
    /// file that settled on holding nothing is taken as it is — emptying a
    /// list is the owner's to do. True when a source settled on a new state.
    fn follow_files(&mut self, journal: &Journal) -> bool {
        let mut changed = false;
        for stamp in &mut self.stamps {
            let t = modified(&stamp.path);
            let moved = t != stamp.seen;
            stamp.seen = t;
            if t == stamp.taken {
                continue;
            }
            let (is_list, what) = entries_of(&stamp.path);
            if moved && !is_list {
                journal.log(format_args!(
                    "source-unsettled {} {what}",
                    stamp.path.display()
                ));
                continue;
            }
            stamp.taken = t;
            changed = true;
            journal.log(format_args!(
                "source {} changed {what}",
                stamp.path.display()
            ));
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
        let built = build(&s, &dir, &cache);
        assert_eq!(built.lists.match_domain("x.example.com"), ["custom"]);
        assert_eq!(built.lists.match_domain("telegram.org"), ["telegram"]);
        assert_eq!(built.missing.len(), 1);
        assert!(built.missing[0].starts_with("telegram https://h/b.lst: "));
        assert!(built.stale.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The file source is kept as a copy: gone from disk, it still builds,
    /// and says so. A file that reads and holds nothing is taken as it is.
    #[test]
    fn a_file_source_falls_back_on_its_copy() {
        let dir = std::env::temp_dir().join(format!("mac-gate-file-{}", std::process::id()));
        let cache = dir.join("cache");
        let file = dir.join("lists/custom.lst");
        fs::create_dir_all(dir.join("lists")).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::write(&file, "example.com\n").unwrap();
        let s = parse(
            "[[list]]\nname = \"custom\"\nsources = [\"lists/custom.lst\"]\n\
             [[tunnel]]\nname = \"t\"\nconf = \"t.conf\"\n\
             [[rule]]\nname = \"r\"\nwhen = \"always\"\nlists = [\"custom\"]\ntunnels = [\"t\"]\n",
        )
        .unwrap();
        let built = build(&s, &dir, &cache);
        assert_eq!(built.lists.match_domain("example.com"), ["custom"]);
        assert!(built.stale.is_empty() && built.missing.is_empty());

        fs::remove_file(&file).unwrap();
        let built = build(&s, &dir, &cache);
        assert_eq!(built.lists.match_domain("example.com"), ["custom"]);
        assert_eq!(built.stale, ["custom lists/custom.lst".to_owned()]);
        assert!(built.missing.is_empty());

        // Emptied on purpose: the copy is neither written nor read.
        fs::write(&file, "\n").unwrap();
        let built = build(&s, &dir, &cache);
        assert!(built.lists.match_domain("example.com").is_empty());
        assert!(built.stale.is_empty() && built.missing.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A file truncated in place before it is filled is not read halfway:
    /// the step that catches it holding nothing waits, and the lists never
    /// lose the source. Settled on nothing, it is taken as it is.
    #[test]
    fn a_file_being_written_waits_for_the_next_step() {
        let dir = std::env::temp_dir().join(format!("mac-gate-write-{}", std::process::id()));
        let cache = dir.join("cache");
        let file = dir.join("lists/custom.lst");
        fs::create_dir_all(dir.join("lists")).unwrap();
        fs::create_dir_all(&cache).unwrap();
        fs::write(&file, "example.com\n").unwrap();
        let s = parse(
            "[[list]]\nname = \"custom\"\nsources = [\"lists/custom.lst\"]\n\
             [[tunnel]]\nname = \"t\"\nconf = \"t.conf\"\n\
             [[rule]]\nname = \"r\"\nwhen = \"always\"\nlists = [\"custom\"]\ntunnels = [\"t\"]\n",
        )
        .unwrap();
        let journal = Journal::open(Some(&dir.join("journal"))).unwrap();
        let mut u = Updater::new(s, &dir, &cache, dir.join("update"));
        assert!(!u.follow_files(&journal));

        // The editor truncates in place and the step catches it there.
        fs::write(&file, "").unwrap();
        assert!(!u.follow_files(&journal));
        // Filled before the next step: the change is taken whole, once.
        fs::write(&file, "example.com\nexample.org\n").unwrap();
        assert!(u.follow_files(&journal));
        assert!(!u.follow_files(&journal));

        // Emptied on purpose: waited out once, then taken as it is.
        fs::write(&file, "").unwrap();
        assert!(!u.follow_files(&journal));
        assert!(u.follow_files(&journal));
        assert!(!u.follow_files(&journal));
        fs::remove_dir_all(&dir).unwrap();
    }
}
