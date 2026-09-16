//! Installation as a launchd service. The binaries go to a directory of
//! root, so that a service of root runs nothing the user can replace; the
//! settings, their file sources and the tunnel files go beside them, and
//! the URL sources are fetched into the cache. The service sets the DNS of
//! the Mac to itself and takes everything back when stopped; `off` stops it
//! and sweeps what a crash left behind.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, chown, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::command;
use crate::config::{self, Settings};
use crate::net;
use crate::pf::Pf;
use crate::sources;
use crate::sysdns;
use crate::tunnel::{self, Tools};
use crate::upstream::Upstream;

const LABEL: &str = "mac-gate";
const SERVICE: &str = "system/mac-gate";
pub const LIBEXEC: &str = "/usr/local/libexec/mac-gate";
const ETC: &str = "/usr/local/etc/mac-gate";
const STATE_DIR: &str = "/var/db/mac-gate";
pub const STATE: &str = "/var/db/mac-gate/routes";
const JOURNAL: &str = "/var/log/mac-gate.log";
const ERRLOG: &str = "/var/log/mac-gate.err";
const PLIST: &str = "/Library/LaunchDaemons/mac-gate.plist";
/// So that `sudo mac-gate off` works from any directory.
const LINK: &str = "/usr/local/bin/mac-gate";
pub const RUN_DIR: &str = "/var/run/amneziawg";
const LAUNCHCTL: &str = "/bin/launchctl";
const STEP: Duration = Duration::from_secs(10);
/// The daemon takes everything back within the plist's `ExitTimeOut`.
const EXIT_WAIT: Duration = Duration::from_secs(70);
const READY_WAIT: Duration = Duration::from_secs(30);
const CONFIRM_WAIT: Duration = Duration::from_secs(30);

/// What `install` copies, from wherever the owner has it.
#[derive(Debug, PartialEq, Eq)]
pub struct Sources {
    /// The settings; their file sources and tunnel files are found beside
    /// them.
    pub config: PathBuf,
    pub awg_go: PathBuf,
    pub awg: PathBuf,
}

fn bin(name: &str) -> PathBuf {
    Path::new(LIBEXEC).join(name)
}

fn settings_path() -> PathBuf {
    Path::new(ETC).join("mac-gate.toml")
}

fn cache_path() -> PathBuf {
    Path::new(STATE_DIR).join(sources::CACHE)
}

/// The service: the daemon as the DNS of the Mac, started again at once
/// when it dies.
pub fn plist() -> String {
    let args = [
        bin("mac-gate").display().to_string(),
        "run".to_owned(),
        "--config".to_owned(),
        settings_path().display().to_string(),
        "--state".to_owned(),
        STATE.to_owned(),
        "--journal".to_owned(),
        JOURNAL.to_owned(),
        "--libexec".to_owned(),
        LIBEXEC.to_owned(),
        "--system-dns".to_owned(),
    ];
    let args = args.iter().fold(String::new(), |mut s, a| {
        let _ = writeln!(s, "        <string>{a}</string>");
        s
    });
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>1</integer>
    <key>ExitTimeOut</key><integer>60</integer>
    <key>StandardErrorPath</key><string>{ERRLOG}</string>
</dict>
</plist>
"#
    )
}

async fn require_root() -> Result<(), Box<dyn Error>> {
    let id = command::run("/usr/bin/id", &["-u"], None, STEP).await?;
    if id.trim() == "0" {
        Ok(())
    } else {
        Err("run with sudo".into())
    }
}

fn ignore_missing(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

fn make_dir(path: &Path, mode: u32) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// Copies beside the target and renames over it: the target is whole at
/// every moment, and never open for writing.
fn put(from: &Path, to: &Path, mode: u32) -> io::Result<()> {
    let tmp = PathBuf::from(format!("{}.new", to.display()));
    ignore_missing(fs::remove_file(&tmp))?;
    fs::copy(from, &tmp)?;
    // A copy by root keeps the owner of the source on macOS: a binary of
    // the user, run by a service of root, would be the user's to replace.
    chown(&tmp, Some(0), Some(0))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, to)
}

fn put_text(text: &str, to: &Path, mode: u32) -> io::Result<()> {
    let tmp = PathBuf::from(format!("{}.new", to.display()));
    fs::write(&tmp, text)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, to)
}

/// The directory of the settings, where their file sources are.
fn base_of(settings: &Path) -> &Path {
    settings
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// The file sources and the tunnel files beside the installed settings, at
/// the same relative paths. The directory is written anew before: a file
/// dropped from the settings, a key among them, does not linger there.
fn put_files(settings: &Settings, base: &Path) -> io::Result<usize> {
    ignore_missing(fs::remove_dir_all(ETC))?;
    make_dir(Path::new(ETC), 0o700)?;
    let lists = settings.files().map(|rel| (rel, 0o644));
    let confs = settings.tunnels.iter().map(|t| (t.conf.as_path(), 0o600));
    let mut n = 0;
    for (rel, mode) in lists.chain(confs) {
        let to = Path::new(ETC).join(rel);
        if let Some(dir) = to.parent() {
            make_dir(dir, 0o700)?;
        }
        put(&base.join(rel), &to, mode)?;
        n += 1;
    }
    Ok(n)
}

/// Every file source read and every URL fetched, each with entries. A URL
/// that fails with a copy in the cache keeps the copy; without one, the
/// install fails. Returns the fetched texts, for the cache.
async fn check_sources(
    settings: &Settings,
    base: &Path,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    for rel in settings.files() {
        let path = base.join(rel);
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let n = sources::check(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("source {}: {n} entries", path.display());
    }
    let mut fetched = Vec::new();
    for url in settings.urls() {
        let got = sources::fetch(url, None)
            .await
            .map_err(|e| e.to_string())
            .and_then(|text| sources::check(&text).map(|n| (text, n)));
        match got {
            Ok((text, n)) => {
                println!("source {url}: {n} entries");
                fetched.push((url.to_owned(), text));
            }
            Err(e) if sources::cache_file(&cache_path(), url).is_file() => {
                println!("source {url}: {e}; the cached copy stays");
            }
            Err(e) => return Err(format!("source {url}: {e}").into()),
        }
    }
    Ok(fetched)
}

/// Checks the sources, stops what runs, copies and starts. A bad source
/// fails before anything changes.
pub async fn install(src: &Sources) -> Result<(), Box<dyn Error>> {
    require_root().await?;
    let settings = config::load(&src.config)?;
    let base = base_of(&src.config);
    // The directory is written anew below: the settings in it would be
    // gone before they are copied.
    if fs::canonicalize(base).ok() == fs::canonicalize(ETC).ok() {
        return Err(format!(
            "{}: install from a copy outside {ETC}",
            src.config.display()
        )
        .into());
    }
    crate::daemon::load_confs(&settings, base)?;
    for f in [&src.awg_go, &src.awg] {
        if !f.is_file() {
            return Err(format!("{}: not a file", f.display()).into());
        }
    }
    let fetched = check_sources(&settings, base).await?;
    let me = std::env::current_exe()?;
    stop().await?;
    make_dir(Path::new(LIBEXEC), 0o755)?;
    put(&me, &bin("mac-gate"), 0o755)?;
    put(&src.awg_go, &bin("amneziawg-go"), 0o755)?;
    put(&src.awg, &bin("awg"), 0o755)?;
    let files = put_files(&settings, base)?;
    put(&src.config, &settings_path(), 0o644)?;
    make_dir(Path::new(STATE_DIR), 0o700)?;
    make_dir(&cache_path(), 0o700)?;
    for (url, text) in &fetched {
        sources::write_cache(&sources::cache_file(&cache_path(), url), text)?;
    }
    println!(
        "installed: {LIBEXEC}; settings with {} rules, {} tunnels, {} lists and {files} files in {ETC}; {} sources fetched",
        settings.rules.len(),
        settings.tunnels.len(),
        settings.lists.len(),
        fetched.len()
    );
    link();
    start().await
}

/// The command on the path; a file of someone else there is left alone.
fn link() {
    let target = bin("mac-gate");
    match fs::read_link(LINK) {
        Ok(t) if t == target => return,
        Ok(_) | Err(_) if Path::new(LINK).symlink_metadata().is_ok() => {
            println!("{LINK} exists and is not ours; left as it is");
            return;
        }
        _ => {}
    }
    if let Err(e) = symlink(&target, LINK) {
        println!("{LINK}: {e}");
    }
}

fn unlink() -> io::Result<()> {
    match fs::read_link(LINK) {
        Ok(t) if t == bin("mac-gate") => fs::remove_file(LINK),
        _ => Ok(()),
    }
}

pub async fn uninstall() -> Result<(), Box<dyn Error>> {
    require_root().await?;
    stop().await?;
    unlink()?;
    for dir in [LIBEXEC, ETC, STATE_DIR] {
        ignore_missing(fs::remove_dir_all(dir))?;
    }
    for file in [JOURNAL, ERRLOG] {
        ignore_missing(fs::remove_file(file))?;
    }
    println!("uninstalled");
    Ok(())
}

pub async fn on() -> Result<(), Box<dyn Error>> {
    require_root().await?;
    if !bin("mac-gate").is_file() {
        return Err("not installed".into());
    }
    if loaded().await {
        println!("already on");
        return Ok(());
    }
    start().await
}

pub async fn off() -> Result<(), Box<dyn Error>> {
    require_root().await?;
    stop().await
}

async fn loaded() -> bool {
    command::run(LAUNCHCTL, &["print", SERVICE], None, STEP)
        .await
        .is_ok()
}

fn journal_len() -> u64 {
    fs::metadata(JOURNAL).map_or(0, |m| m.len())
}

/// Journal lines written since `from`.
fn journal_since(from: u64) -> String {
    let text = fs::read(JOURNAL).unwrap_or_default();
    let from = usize::try_from(from).unwrap_or(usize::MAX).min(text.len());
    String::from_utf8_lossy(text.get(from..).unwrap_or_default()).into_owned()
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Puts the service in place and waits for its answer on 127.0.0.1:53;
/// none, and it is taken back, lest the Mac stay without names.
async fn start() -> Result<(), Box<dyn Error>> {
    let local = Upstream {
        server: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
        bound_if: None,
    };
    // Its answer would pass for ours below.
    if net::query_a(local, "example.com.", Duration::from_secs(1))
        .await
        .is_ok()
    {
        return Err("something else answers on 127.0.0.1:53".into());
    }
    put_text(&plist(), Path::new(PLIST), 0o644)?;
    let from = journal_len();
    if let Err(e) = command::run(LAUNCHCTL, &["bootstrap", "system", PLIST], None, STEP).await {
        // Left in place, it would start at the next boot.
        ignore_missing(fs::remove_file(PLIST))?;
        return Err(e.into());
    }
    let start = Instant::now();
    let mut answered = false;
    while start.elapsed() < READY_WAIT {
        if net::query_a(local, "example.com.", Duration::from_secs(2))
            .await
            .is_ok()
        {
            answered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if !answered {
        let seen = tail(&journal_since(from), 10);
        let err = tail(&fs::read_to_string(ERRLOG).unwrap_or_default(), 10);
        println!(
            "no answer on 127.0.0.1:53 in {}s; taking back",
            READY_WAIT.as_secs()
        );
        stop().await?;
        return Err(format!("not started\njournal:\n{seen}\nerrors:\n{err}").into());
    }
    println!(
        "on: answers on 127.0.0.1:53 after {}ms",
        start.elapsed().as_millis()
    );
    while start.elapsed() < CONFIRM_WAIT {
        let seen = journal_since(from);
        if let Some(line) = seen.lines().find(|l| l.contains(" confirm ")) {
            let dns = seen.lines().find(|l| l.contains(" dns "));
            println!("tunnel: {}", line.split_once(' ').map_or(line, |(_, r)| r));
            if let Some(d) = dns {
                println!("{}", d.split_once(' ').map_or(d, |(_, r)| r));
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    println!("tunnel not confirmed yet; listed names are refused meanwhile; journal {JOURNAL}");
    Ok(())
}

/// Stops the service, which takes everything back, and removes it from
/// launchd for good; then takes back whatever a crash left.
async fn stop() -> Result<(), Box<dyn Error>> {
    if loaded().await {
        command::run(LAUNCHCTL, &["bootout", SERVICE], None, EXIT_WAIT).await?;
        println!("service stopped");
    }
    ignore_missing(fs::remove_file(PLIST))?;
    let pattern = format!("{} run .*", bin("mac-gate").display());
    let start = Instant::now();
    while command::run("/usr/bin/pgrep", &["-f", "-x", &pattern], None, STEP)
        .await
        .is_ok()
    {
        if start.elapsed() >= EXIT_WAIT {
            return Err("the daemon does not exit".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    sweep().await
}

/// What a crash leaves: the tunnel, which takes its routes along; the pf
/// anchor and its reference; the DNS of the services; the owner's flag.
async fn sweep() -> Result<(), Box<dyn Error>> {
    let dir = Path::new(STATE_DIR);
    let tools = Tools {
        go: bin("amneziawg-go"),
        awg: bin("awg"),
        run_dir: PathBuf::from(RUN_DIR),
    };
    let strays = tunnel::kill_strays(&tools).await;
    if !strays.is_empty() {
        println!("left by a crash: amneziawg-go {strays:?} stopped");
    }
    if let Ok(names) = fs::read_dir(RUN_DIR) {
        for path in names.filter_map(Result::ok).map(|e| e.path()) {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with("mac-gate-") && name.ends_with(".name") {
                let _ = fs::remove_file(&path);
            }
        }
    }
    if dir.join("pf-token").exists() {
        Pf::new(dir).release().await?;
        println!("left by a crash: pf anchor released");
    }
    if sysdns::saved(dir) {
        let n = sysdns::give_back(dir).await?;
        println!("left by a crash: DNS put back on {n} services");
    }
    ignore_missing(fs::remove_file(dir.join(crate::daemon::OWNER_FLAG)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// plutil checks the plist without root.
    #[test]
    fn plist_is_valid() {
        let path = std::env::temp_dir().join(format!("mac-gate-{}.plist", std::process::id()));
        fs::write(&path, plist()).unwrap();
        let ok = std::process::Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        fs::remove_file(&path).unwrap();
        assert!(ok);
        let p = plist();
        assert!(p.contains("<string>--system-dns</string>"));
        assert!(p.contains("<string>/var/db/mac-gate/routes</string>"));
        assert!(p.contains(
            "<string>--config</string>\n        <string>/usr/local/etc/mac-gate/mac-gate.toml</string>"
        ));
        assert_eq!(base_of(Path::new("a.toml")), Path::new("."));
        assert_eq!(base_of(Path::new("/x/a.toml")), Path::new("/x"));
    }

    #[test]
    fn tail_lines() {
        assert_eq!(tail("a\nb\nc\n", 2), "b\nc");
        assert_eq!(tail("a", 5), "a");
    }
}
