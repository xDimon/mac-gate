//! The daemon: the resolver as the DNS of the Mac, a link per tunnel, and a
//! watch that follows the network, sleep, upstream fake addresses and the
//! country, puts the rules in force, expires host routes and keeps them
//! on disk.
//!
//! The kill switch has reasons of its own, per rule, each set and cleared
//! apart: no tunnel of the rule carries, work is under way, the owner said
//! so. Any one of them refuses the names of the rule. pf holds the
//! addresses to the tunnels of their rule all the time, reasons or not, so
//! that neither a dead amneziawg-go nor a dead daemon lets them out; a stop
//! takes it all back, a crash does not.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio::sync::watch::{self, Receiver, Sender};
use tokio::task::JoinHandle;

use crate::config::{self, Settings};
use crate::geo::{self, Asked};
use crate::link::{Ctl, Link};
use crate::net::{self, Clock, Network, RouteEvents};
use crate::pf::{Pf, write_private};
use crate::resolver::{Journal, LinkState, Reasons, Resolver};
use crate::route::RouteSocket;
use crate::sources::{self, Built, Updater};
use crate::state;
use crate::sysdns;
use crate::tunnel::{self, Conf, Tools};

const TICK: Duration = Duration::from_secs(1);
const NET_POLL: Duration = Duration::from_secs(30);
const NET_SETTLE: Duration = Duration::from_secs(1);
const FAKEIP_EVERY: Duration = Duration::from_mins(5);
const SAVE_EVERY: Duration = Duration::from_mins(1);
const SWEEP_EVERY: Duration = Duration::from_mins(10);
const STATUS_EVERY: Duration = Duration::from_mins(10);
/// After a wake on the same network, the country is asked again only when
/// the last answer is older than this.
const COUNTRY_AFTER: Duration = Duration::from_hours(3);
const COUNTRY_RETRY: Duration = Duration::from_mins(5);
/// While nothing is known of the country: the rules written for this one
/// hold, so that a mistake sends nothing past a tunnel.
const COUNTRY_DEFAULT: &str = "RU";
/// The tunnels of a daemon that died keep carrying until the new ones take
/// the routes, or this long.
const STRAYS_WAIT: Duration = Duration::from_secs(20);
const LINKS_EXIT: Duration = Duration::from_secs(15);
/// The owner's reason for the kill switch, next to the state file.
pub const OWNER_FLAG: &str = "killswitch";
/// The owner's country, next to the state file; without it, the country
/// is asked of the services.
pub const COUNTRY_FLAG: &str = "country";
/// The last country the services agreed on, and when.
const COUNTRY_SEEN: &str = "country-seen";

/// The directory of a file. That of the state file also keeps the pf files,
/// the cached sources and the owner's flags; that of the settings, the file
/// sources and the tunnel files.
fn dir_of(file: &Path) -> PathBuf {
    file.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_owned()
}

fn raise(flag: &Path) -> io::Result<()> {
    fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(flag)
        .map(drop)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", flag.display())))
}

fn lower(flag: &Path) -> io::Result<()> {
    match fs::remove_file(flag) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", flag.display()))),
    }
}

/// Asks the daemon to fetch every source now; it looks every second.
pub fn request_update(state: &Path) -> io::Result<()> {
    raise(&dir_of(state).join(sources::UPDATE_FLAG))
}

/// Sets or takes away the owner's reason; the daemon looks every second.
pub fn owner_killswitch(state: &Path, on: bool) -> io::Result<()> {
    let flag = dir_of(state).join(OWNER_FLAG);
    if on { raise(&flag) } else { lower(&flag) }
}

/// Sets the owner's country, or none to ask the services; the daemon
/// looks every second.
pub fn owner_country(state: &Path, code: Option<&str>) -> io::Result<()> {
    let flag = dir_of(state).join(COUNTRY_FLAG);
    match code {
        Some(c) => write_private(&flag, &format!("{c}\n"))
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", flag.display()))),
        None => lower(&flag),
    }
}

/// Two capital letters, as the flag and the settings have them.
pub fn country_code(text: &str) -> Option<&str> {
    let t = text.trim();
    (t.len() == 2 && t.bytes().all(|b| b.is_ascii_uppercase())).then_some(t)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// The settings file: the lists and their sources, the tunnels and the
    /// rules.
    pub settings: PathBuf,
    pub state: PathBuf,
    pub journal: Option<PathBuf>,
    pub listen: SocketAddr,
    pub tunnel_dns: Ipv4Addr,
    /// Holds amneziawg-go and awg.
    pub libexec: PathBuf,
    /// Seconds a host route lives after its last answer.
    pub window: u64,
    /// Listed names go first to a network whose DNS answers with fake
    /// addresses, and its subnets are left to the router.
    pub use_fakeip: bool,
    /// Every network service of the Mac asks the resolver; a stop puts
    /// back what they had.
    pub system_dns: bool,
}

/// The tunnel files of the settings, each parsed. Two with one address
/// would fight over it on the Mac.
pub fn load_confs(settings: &Settings, base: &Path) -> Result<Vec<Conf>, String> {
    let mut confs: Vec<Conf> = Vec::new();
    for t in &settings.tunnels {
        let path = base.join(&t.conf);
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c = Conf::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some((other, _)) = settings
            .tunnels
            .iter()
            .zip(&confs)
            .find(|(_, o)| o.address == c.address)
        {
            return Err(format!(
                "tunnel {}: address {} as in tunnel {}",
                t.name, c.address, other.name
            ));
        }
        confs.push(c);
    }
    Ok(confs)
}

/// The rule a saved address goes to: its rule by name, or, in a file of an
/// earlier version, the first rule that has its list.
fn rule_of(settings: &Settings, name: &str) -> Option<usize> {
    settings
        .rules
        .iter()
        .position(|r| r.name == name)
        .or_else(|| {
            settings
                .rules
                .iter()
                .position(|r| r.lists.iter().any(|l| l == name))
        })
}

/// The country: the owner's, else the last the services agreed on, else
/// the default.
struct Country {
    owner: Option<String>,
    /// The code and the unix seconds of the answer.
    seen: Option<(String, u64)>,
    /// The network of the last answer: a wake on it asks again only after
    /// a while.
    seen_on: Option<Network>,
}

impl Country {
    fn load(dir: &Path) -> Self {
        let owner = fs::read_to_string(dir.join(COUNTRY_FLAG))
            .ok()
            .and_then(|t| country_code(&t).map(str::to_owned));
        let seen = fs::read_to_string(dir.join(COUNTRY_SEEN))
            .ok()
            .and_then(|t| {
                let mut f = t.split_whitespace();
                let code = country_code(f.next()?)?.to_owned();
                Some((code, f.next()?.parse().ok()?))
            });
        Self {
            owner,
            seen,
            seen_on: None,
        }
    }

    fn now(&self) -> (&str, &'static str) {
        match (&self.owner, &self.seen) {
            (Some(c), _) => (c, "owner"),
            (None, Some((c, _))) => (c, "services"),
            (None, None) => (COUNTRY_DEFAULT, "default"),
        }
    }

    fn stale(&self) -> bool {
        self.seen
            .as_ref()
            .is_none_or(|(_, at)| state::now().saturating_sub(*at) > COUNTRY_AFTER.as_secs())
    }
}

/// The sources of the lists: the settings, and the cache and the flag next
/// to the state file.
fn open_sources(cfg: &Config, settings: Settings) -> Result<Updater, Box<dyn Error>> {
    let dir = dir_of(&cfg.state);
    let cache = dir.join(sources::CACHE);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&cache)?;
    Ok(Updater::new(
        settings,
        &dir_of(&cfg.settings),
        &cache,
        dir.join(sources::UPDATE_FLAG),
    ))
}

fn log_start(
    journal: &Journal,
    cfg: &Config,
    settings: &Settings,
    confs: &[Conf],
    built: &Built,
    saved: usize,
) {
    let lists = &built.lists;
    let ignored: Vec<String> = settings
        .tunnels
        .iter()
        .zip(confs)
        .filter(|(_, c)| !c.ignored.is_empty())
        .map(|(t, c)| format!("{}:{}", t.name, c.ignored.join(",")))
        .collect();
    journal.log(format_args!(
        "start daemon rules={} tunnels={} lists={} suffixes={} subnets={} rejected={} missing={} stale={} saved_hosts={saved} listen={} tunnel_dns={} window={}s use_fakeip={} conf_ignored={ignored:?}",
        settings.rules.len(),
        settings.tunnels.len(),
        settings.lists.len(),
        lists.suffix_count(),
        lists.subnets().count(),
        lists.rejected.len(),
        built.missing.len(),
        built.stale.len(),
        cfg.listen,
        cfg.tunnel_dns,
        cfg.window,
        if cfg.use_fakeip { "auto" } else { "off" },
    ));
    for line in &lists.rejected {
        journal.log(format_args!("rejected {line}"));
    }
    for line in &built.missing {
        journal.log(format_args!("source-missing {line}"));
    }
    for line in &built.stale {
        journal.log(format_args!("source-stale {line}"));
    }
}

/// The saved hosts by rule, and those a crash left in the tables of pf:
/// answered since the last save, missing from the state, they would lose
/// both route and block. Their last answer is unknown; now it is.
async fn hosts_to_restore(
    settings: &Settings,
    saved: state::Hosts,
    pf: &Pf,
    journal: &Journal,
) -> Vec<(Ipv4Addr, usize, u64)> {
    let now = state::now();
    let mut hosts: HashMap<Ipv4Addr, (usize, u64)> = saved
        .into_iter()
        .filter_map(|(ip, h)| Some((ip, (rule_of(settings, &h.rule)?, h.last))))
        .collect();
    let mut held = 0;
    for (rule, ip) in pf.held_hosts(settings.rules.len()).await {
        hosts.entry(ip).or_insert_with(|| {
            held += 1;
            (rule, now)
        });
    }
    if held > 0 {
        journal.log(format_args!("pf held hosts added={held}"));
    }
    hosts
        .into_iter()
        .map(|(ip, (rule, last))| (ip, rule, last))
        .collect()
}

/// A link task per tunnel, each told whether a rule in force takes it.
fn spawn_links(
    settings: &Settings,
    confs: Vec<Conf>,
    resolver: &Arc<Resolver>,
    tools: &Tools,
    net: &Receiver<Option<Network>>,
) -> Vec<(Sender<Ctl>, JoinHandle<()>)> {
    let wanted = resolver.wanted();
    let mut links = Vec::new();
    for (i, (t, conf)) in settings.tunnels.iter().zip(confs).enumerate() {
        let (tx, rx) = watch::channel(Ctl {
            wanted: wanted.get(i).copied().unwrap_or(false),
            ..Ctl::default()
        });
        let link = Link::new(
            i,
            t.name.clone(),
            Arc::clone(resolver),
            conf,
            tools.clone(),
            net.clone(),
            rx,
        );
        links.push((tx, tokio::spawn(link.run())));
    }
    links
}

pub async fn run(cfg: Config) -> Result<(), Box<dyn Error>> {
    let settings = config::load(&cfg.settings)?;
    let confs = load_confs(&settings, &dir_of(&cfg.settings))?;
    let updater = open_sources(&cfg, settings.clone())?;
    let saved = state::load(&cfg.state)?;
    let journal = Journal::open(cfg.journal.as_deref())?;
    let dir = dir_of(&cfg.state);
    // A source without a copy yet is fetched in the first step.
    let built = updater.build();
    log_start(&journal, &cfg, &settings, &confs, &built, saved.len());
    let udp = UdpSocket::bind(cfg.listen).await?;
    let tcp = TcpListener::bind(cfg.listen).await?;
    let events = RouteEvents::open()?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let pf = Pf::new(&dir);
    pf.enable().await?;
    let hosts = hosts_to_restore(&settings, saved, &pf, &journal).await;
    let resolver = Arc::new(Resolver::new(
        built.lists,
        &settings.rules,
        settings.tunnels.iter().map(|t| t.name.clone()).collect(),
        cfg.tunnel_dns,
        RouteSocket::open()?,
        journal,
        Some(pf),
    ));
    // The servers written as addresses are let out before the first answer.
    for (i, c) in confs.iter().enumerate() {
        if let Some(ip) = c.endpoint_ip() {
            resolver.set_link(
                i,
                LinkState {
                    endpoint: Some(ip),
                    ..LinkState::default()
                },
            );
        }
    }
    let country = Country::load(&dir);
    let (code, from) = country.now();
    resolver
        .journal
        .log(format_args!("country {code} from={from}"));
    for (rule, on) in resolver.set_country(code) {
        resolver.journal.log(format_args!(
            "rule {rule} {}",
            if on { "in force" } else { "out of force" }
        ));
    }
    resolver.load_hosts(hosts);
    // The kill switch before the first answer: no tunnel yet, so the saved
    // hosts and the subnets are held everywhere.
    resolver.sync_pf().await?;
    tokio::spawn(crate::serve(Arc::clone(&resolver), udp, tcp));
    let (net_tx, net_rx) = watch::channel(None);
    let nudge = Arc::new(Notify::new());
    tokio::spawn(track_network(
        Arc::clone(&resolver),
        events,
        net_tx,
        Arc::clone(&nudge),
    ));
    let tools = Tools {
        go: cfg.libexec.join("amneziawg-go"),
        awg: cfg.libexec.join("awg"),
        run_dir: PathBuf::from(crate::install::RUN_DIR),
    };
    // Asked before any tunnel of this daemon is up: all of them are strays.
    let strays = tunnel::stray_pids(&tools).await;
    let links = spawn_links(&settings, confs, &resolver, &tools, &net_rx);
    let mut moved = net_rx.clone();
    let mut watch = Watch::new(resolver, &cfg, net_rx, nudge, updater, links, country);
    watch.missing = built.missing;
    watch.stale = built.stale;
    if !strays.is_empty() {
        watch.strays = Some((strays, Instant::now()));
    }
    // Serving already: from here on the Mac asks the resolver.
    watch.take_dns().await;
    loop {
        tokio::select! {
            () = tokio::time::sleep(TICK) => {}
            Ok(()) = moved.changed() => {}
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
        watch.step().await;
    }
    watch.stop().await;
    Ok(())
}

/// Follows the network apart from the watch and the links, which may sit
/// in a probe for many seconds: the resolver asks the DNS of a new network
/// at once, and the others hear of it through `tx`.
async fn track_network(
    resolver: Arc<Resolver>,
    events: RouteEvents,
    tx: Sender<Option<Network>>,
    nudge: Arc<Notify>,
) {
    let mut events = Some(events);
    loop {
        let n = net::current().await;
        if n != *tx.borrow() {
            resolver.set_network(n.as_ref());
            // No upstream FakeIP until it is seen in this network.
            resolver.set_use_fakeip(false);
            tx.send_replace(n);
        }
        let event = async {
            match &events {
                Some(e) => e.next().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = tokio::time::sleep(NET_POLL) => {}
            () = nudge.notified() => {}
            got = event => match got {
                // The addresses and routes of a change come in a burst.
                Ok(()) => tokio::time::sleep(NET_SETTLE).await,
                Err(e) => {
                    resolver
                        .journal
                        .log(format_args!("route-events-fail {e}; polling only"));
                    events = None;
                }
            },
        }
    }
}

struct Watch {
    resolver: Arc<Resolver>,
    state_path: PathBuf,
    dir: PathBuf,
    window: u64,
    network: Option<Network>,
    /// The network as the tracker sees it; followed on the next step.
    net: Receiver<Option<Network>>,
    /// Makes the tracker look at the network now.
    nudge: Arc<Notify>,
    fakeip_at: Instant,
    save_at: Instant,
    sweep_at: Instant,
    status_at: Instant,
    clock: Clock,
    /// Trust a resolver answering with fake addresses in the network.
    use_fakeip: bool,
    /// What each link is told, and its task.
    links: Vec<(Sender<Ctl>, JoinHandle<()>)>,
    wakes: u64,
    /// The reasons of the rules in force, as last written.
    reasons: Vec<(String, Reasons)>,
    country: Country,
    /// The country is asked at this time.
    country_at: Option<Instant>,
    /// Asking now: on which network, and the task.
    asking: Option<(Option<Network>, JoinHandle<Asked>)>,
    /// The DNS of the Mac is ours; the directory of what it had.
    dns_dir: Option<PathBuf>,
    /// The services are looked at again at this time: a new network may
    /// bring one that does not ask the resolver yet.
    dns_at: Option<Instant>,
    updater: Updater,
    /// Sources with neither a file nor a copy, and file sources running on
    /// their copy, as the last build found them. Written to the journal
    /// with every status line: a source that never comes back would
    /// otherwise be named once, at the start, and never again.
    missing: Vec<String>,
    stale: Vec<String>,
    /// amneziawg-go of a daemon that died, and since when they wait.
    strays: Option<(Vec<u32>, Instant)>,
}

impl Watch {
    fn new(
        resolver: Arc<Resolver>,
        cfg: &Config,
        net: Receiver<Option<Network>>,
        nudge: Arc<Notify>,
        updater: Updater,
        links: Vec<(Sender<Ctl>, JoinHandle<()>)>,
        country: Country,
    ) -> Self {
        let now = Instant::now();
        let dir = dir_of(&cfg.state);
        Self {
            resolver,
            state_path: cfg.state.clone(),
            window: cfg.window,
            network: None,
            net,
            nudge,
            fakeip_at: now,
            save_at: now + SAVE_EVERY,
            sweep_at: now + SWEEP_EVERY,
            status_at: now + STATUS_EVERY,
            clock: Clock::default(),
            use_fakeip: cfg.use_fakeip,
            links,
            wakes: 0,
            reasons: Vec::new(),
            country,
            country_at: None,
            asking: None,
            dns_dir: cfg.system_dns.then(|| dir.clone()),
            dns_at: None,
            updater,
            missing: Vec::new(),
            stale: Vec::new(),
            strays: None,
            dir,
        }
    }

    fn log(&self, event: std::fmt::Arguments<'_>) {
        self.resolver.journal.log(event);
    }

    /// Sets the services that do not ask the resolver yet; a failure is
    /// tried again after a while.
    async fn take_dns(&mut self) {
        let Some(dir) = &self.dns_dir else {
            return;
        };
        match sysdns::take_over(dir).await {
            Ok(n) => {
                self.dns_at = None;
                if n > 0 {
                    self.log(format_args!("dns set services={n}"));
                }
            }
            Err(e) => {
                self.dns_at = Some(Instant::now() + NET_POLL);
                self.resolver
                    .journal
                    .burst("dns-fail", format_args!("dns-fail {e}"));
            }
        }
    }

    async fn step(&mut self) {
        let now = Instant::now();
        if let Some(gap) = self.clock.slept() {
            self.log(format_args!("wake slept={}s", gap.as_secs()));
            self.wakes += 1;
            self.nudge.notify_one();
            if self.country.stale() {
                self.country_at = Some(now);
            }
        }
        if self.net.has_changed().unwrap_or(false) {
            self.follow_network();
        }
        if Instant::now() >= self.fakeip_at {
            self.fakeip_at = Instant::now() + FAKEIP_EVERY;
            self.detect_upstream_fakeip().await;
        }
        self.resolver.set_owner(self.dir.join(OWNER_FLAG).exists());
        self.follow_country().await;
        self.tell_links();
        self.resolver.reconcile();
        self.log_reasons();
        let _ = self.resolver.sync_pf().await;
        self.stop_strays().await;
        self.housekeeping().await;
        self.follow_sources().await;
        self.resolver.journal.flush();
    }

    /// Tells every link whether a rule in force takes it, and of wakes.
    fn tell_links(&self) {
        let wanted = self.resolver.wanted();
        for (i, (tx, _)) in self.links.iter().enumerate() {
            let w = wanted.get(i).copied().unwrap_or(false);
            tx.send_if_modified(|c| {
                let changed = c.wanted != w || c.wakes != self.wakes;
                c.wanted = w;
                c.wakes = self.wakes;
                changed
            });
        }
    }

    fn log_reasons(&mut self) {
        let now = self.resolver.reasons();
        for (rule, r) in &now {
            let before = self
                .reasons
                .iter()
                .find(|(n, _)| n == rule)
                .map(|(_, r)| *r);
            if before != Some(*r) {
                self.log(format_args!("killswitch {rule} {r}"));
            }
        }
        self.reasons = now;
    }

    /// The owner's country, and the answer of the services when one came;
    /// a change puts other rules in force.
    async fn follow_country(&mut self) {
        let owner = fs::read_to_string(self.dir.join(COUNTRY_FLAG))
            .ok()
            .and_then(|t| country_code(&t).map(str::to_owned));
        let before = self.country.now().0.to_owned();
        self.country.owner = owner;
        if self
            .asking
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished())
            && let Some((on, task)) = self.asking.take()
        {
            match task.await {
                Ok(asked) => self.take_country(asked, on),
                Err(e) => self.log(format_args!("country-fail task: {e}")),
            }
        }
        let now = Instant::now();
        if self.asking.is_none()
            && self.country_at.is_some_and(|at| now >= at)
            && let Some(n) = self.network.clone()
        {
            self.country_at = None;
            let resolver = Arc::clone(&self.resolver);
            let on = n.clone();
            let task = tokio::spawn(async move { geo::country(&on, |ip| resolver.held(ip)).await });
            self.asking = Some((Some(n), task));
        }
        let (code, from) = self.country.now();
        if code != before {
            let code = code.to_owned();
            self.log(format_args!("country {before} -> {code} from={from}"));
            for (rule, on) in self.resolver.set_country(&code) {
                self.log(format_args!(
                    "rule {rule} {}",
                    if on { "in force" } else { "out of force" }
                ));
            }
        }
    }

    fn take_country(&mut self, asked: Asked, on: Option<Network>) {
        if on != self.network {
            // Asked again on the new network.
            self.log(format_args!(
                "country dropped: network changed; {}",
                asked.shown
            ));
            return;
        }
        let Some(code) = asked.country else {
            self.log(format_args!("country-fail {}", asked.shown));
            self.country_at = Some(Instant::now() + COUNTRY_RETRY);
            return;
        };
        self.log(format_args!("country seen {code}: {}", asked.shown));
        let at = state::now();
        if let Err(e) = write_private(&self.dir.join(COUNTRY_SEEN), &format!("{code} {at}\n")) {
            self.log(format_args!("country-fail save: {e}"));
        }
        self.country.seen = Some((code, at));
        self.country.seen_on = on;
    }

    /// Takes in what the sources brought: new lists, their subnet routes and
    /// pf. Lists without a single entry are refused and the old ones stay.
    async fn follow_sources(&mut self) {
        let tunnel = self.resolver.fetch_iface();
        if !self.updater.poll(tunnel, &self.resolver.journal).await {
            return;
        }
        let built = self.updater.build();
        for line in &built.missing {
            self.log(format_args!("source-missing {line}"));
        }
        for line in &built.stale {
            self.log(format_args!("source-stale {line}"));
        }
        self.missing = built.missing;
        self.stale = built.stale;
        let lists = built.lists;
        if lists.entry_count() == 0 {
            self.log(format_args!(
                "lists-refused no entries; the lists in place stay"
            ));
            return;
        }
        self.log(format_args!(
            "lists reload suffixes={} subnets={} rejected={}",
            lists.suffix_count(),
            lists.subnets().count(),
            lists.rejected.len()
        ));
        self.resolver.set_lists(lists);
        self.resolver.reconcile();
        let _ = self.resolver.sync_pf().await;
    }

    fn follow_network(&mut self) {
        let n = self.net.borrow_and_update().clone();
        if n == self.network {
            return;
        }
        self.log(format_args!(
            "network {} -> {}",
            show(self.network.as_ref()),
            show(n.as_ref())
        ));
        self.resolver.set_network(n.as_ref());
        // No upstream FakeIP until it is seen in this network: the subnets
        // are held meanwhile, not let out past the tunnel.
        self.resolver.set_use_fakeip(false);
        let now = Instant::now();
        self.fakeip_at = now;
        // After the connects of this step, not before: 0.2 s of networksetup.
        self.dns_at = Some(now);
        // A network of its own may be in another country; back on the one
        // of the last answer, as after a wake.
        if n.is_some() && (n != self.country.seen_on || self.country.stale()) {
            self.country_at = Some(now);
        }
        self.network = n;
    }

    async fn detect_upstream_fakeip(&mut self) {
        if !self.use_fakeip {
            return;
        }
        let Some(n) = &self.network else {
            self.resolver.set_use_fakeip(false);
            return;
        };
        match net::upstream_has_fakeip(n.upstream()).await {
            Ok(p) => {
                self.resolver.set_use_fakeip(p);
                self.log(format_args!("upstream-fakeip {p}"));
            }
            Err(e) => self.log(format_args!("upstream-fakeip-fail {e}")),
        }
    }

    /// The tunnels a dead daemon left: they go once the new ones have the
    /// routes, or after a while.
    async fn stop_strays(&mut self) {
        let due = self
            .strays
            .as_ref()
            .is_some_and(|(_, since)| self.resolver.all_routed() || since.elapsed() >= STRAYS_WAIT);
        if due && let Some((pids, _)) = self.strays.take() {
            tunnel::stop_pids(&pids).await;
            self.log(format_args!("stray amneziawg-go stopped {pids:?}"));
        }
    }

    async fn housekeeping(&mut self) {
        let now = Instant::now();
        if self.dns_at.is_some_and(|at| now >= at) {
            self.take_dns().await;
        }
        if now >= self.save_at {
            self.save_at = now + SAVE_EVERY;
            if self.resolver.take_dirty() {
                self.save();
            }
        }
        if now >= self.sweep_at {
            self.sweep_at = now + SWEEP_EVERY;
            let n = self.resolver.expire(state::now(), self.window).await;
            if n > 0 {
                self.log(format_args!("expire {n}"));
            }
        }
        if now >= self.status_at {
            self.status_at = now + STATUS_EVERY;
            let (code, from) = self.country.now();
            self.log(format_args!(
                "status {} missing={} stale={} country={code} from={from} network={}",
                self.resolver.status(),
                self.missing.len(),
                self.stale.len(),
                show(self.network.as_ref()),
            ));
            // Named again every time, not only when they appear: a source
            // that stays away changes nothing and would go quiet.
            for line in &self.missing {
                self.log(format_args!("source-missing {line}"));
            }
            for line in &self.stale {
                self.log(format_args!("source-stale {line}"));
            }
        }
    }

    fn save(&self) {
        if let Err(e) = state::save(&self.state_path, &self.resolver.hosts_snapshot()) {
            self.log(format_args!("save-fail {e}"));
            self.resolver.mark_dirty();
        }
    }

    /// Takes everything back: DNS, tunnels, routes, pf and the owner's
    /// reason. The DNS first: the Mac has names again even if a step
    /// below hangs.
    async fn stop(mut self) {
        let dns = if let Some(dir) = &self.dns_dir {
            match sysdns::give_back(dir).await {
                Ok(n) => n.to_string(),
                Err(e) => format!("fail: {e}"),
            }
        } else {
            "none".to_owned()
        };
        for (tx, _) in &self.links {
            tx.send_modify(|c| c.stop = true);
        }
        for (_, task) in std::mem::take(&mut self.links) {
            let _ = tokio::time::timeout(LINKS_EXIT, task).await;
        }
        let removed = self.resolver.remove_all();
        self.save();
        let pf = match &self.resolver.pf {
            Some(pf) => match pf.release().await {
                Ok(()) => "released".to_owned(),
                Err(e) => format!("fail: {e}"),
            },
            None => "none".to_owned(),
        };
        let _ = fs::remove_file(self.dir.join(OWNER_FLAG));
        self.resolver.journal.flush();
        self.log(format_args!(
            "stop dns_back={dns} routes_removed={removed} hosts_saved={} pf={pf}",
            self.resolver.host_count()
        ));
    }
}

fn show(n: Option<&Network>) -> String {
    n.map_or_else(|| "none".to_owned(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_flags_next_to_the_state() {
        let dir = std::env::temp_dir().join(format!("mac-gate-owner-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let state = dir.join("routes");
        owner_killswitch(&state, true).unwrap();
        owner_killswitch(&state, true).unwrap();
        assert!(dir.join(OWNER_FLAG).exists());
        owner_killswitch(&state, false).unwrap();
        owner_killswitch(&state, false).unwrap();
        assert!(!dir.join(OWNER_FLAG).exists());
        owner_country(&state, Some("DE")).unwrap();
        let c = Country::load(&dir);
        assert_eq!(c.now(), ("DE", "owner"));
        owner_country(&state, None).unwrap();
        owner_country(&state, None).unwrap();
        fs::write(dir.join(COUNTRY_SEEN), "NL 100\n").unwrap();
        let c = Country::load(&dir);
        assert_eq!(c.now(), ("NL", "services"));
        assert!(c.stale());
        fs::write(dir.join(COUNTRY_SEEN), format!("NL {}\n", state::now())).unwrap();
        assert!(!Country::load(&dir).stale());
        fs::remove_file(dir.join(COUNTRY_SEEN)).unwrap();
        assert_eq!(Country::load(&dir).now(), ("RU", "default"));
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(dir_of(Path::new("routes")), PathBuf::from("."));
    }

    #[test]
    fn country_codes() {
        assert_eq!(country_code("DE\n"), Some("DE"));
        assert_eq!(country_code("de"), None);
        assert_eq!(country_code("DEU"), None);
    }

    #[test]
    fn saved_addresses_find_their_rule() {
        let s = config::parse(
            "[[list]]\nname = \"custom\"\nsources = [\"c.lst\"]\n\
             [[list]]\nname = \"telegram\"\nsources = [\"t.lst\"]\n\
             [[tunnel]]\nname = \"t\"\nconf = \"t.conf\"\n\
             [[rule]]\nname = \"always\"\nwhen = \"always\"\nlists = [\"custom\"]\ntunnels = [\"t\"]\n\
             [[rule]]\nname = \"bypass\"\nwhen = \"RU\"\nlists = [\"custom\", \"telegram\"]\ntunnels = [\"t\"]\n",
        )
        .unwrap();
        assert_eq!(rule_of(&s, "bypass"), Some(1));
        assert_eq!(rule_of(&s, "custom"), Some(0));
        assert_eq!(rule_of(&s, "telegram"), Some(1));
        assert_eq!(rule_of(&s, "pf"), None);
    }
}
