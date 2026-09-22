//! One query: to the network DNS as it is, through the tunnel of its rule
//! with routes placed before the answer, or refused. And the routes
//! themselves: which tunnel each rule takes now, and where its hosts and
//! subnets are routed.
//!
//! Names outside the lists of the rules in force never touch a tunnel. A
//! listed name whose rules have no tunnel that carries is refused: the kill
//! switch for DNS.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, RecordType};

use crate::config::{self, When};
use crate::lists::{Lists, Subnet, normalize};
use crate::net::Network;
use crate::pf::{Pf, Shape, Tables};
use crate::route::{Outcome, RouteSocket};
use crate::state::{self, Host, Hosts};
use crate::upstream::Upstream;

/// The fake address range an upstream resolver answers with: such an answer
/// belongs to the router.
const FAKEIP: Subnet = Subnet {
    addr: Ipv4Addr::new(198, 18, 0, 0),
    prefix: 15,
};
/// Never routed into a tunnel: this host, local networks, multicast and
/// reserved space, and the fake range of the router.
const SPECIAL: [Subnet; 9] = [
    Subnet {
        addr: Ipv4Addr::UNSPECIFIED,
        prefix: 8,
    },
    Subnet {
        addr: Ipv4Addr::new(10, 0, 0, 0),
        prefix: 8,
    },
    Subnet {
        addr: Ipv4Addr::new(100, 64, 0, 0),
        prefix: 10,
    },
    Subnet {
        addr: Ipv4Addr::new(127, 0, 0, 0),
        prefix: 8,
    },
    Subnet {
        addr: Ipv4Addr::new(169, 254, 0, 0),
        prefix: 16,
    },
    Subnet {
        addr: Ipv4Addr::new(172, 16, 0, 0),
        prefix: 12,
    },
    Subnet {
        addr: Ipv4Addr::new(192, 168, 0, 0),
        prefix: 16,
    },
    Subnet {
        addr: Ipv4Addr::new(224, 0, 0, 0),
        prefix: 3,
    },
    FAKEIP,
];
/// Firefox turns its own DNS over HTTPS off when this name does not resolve.
const FIREFOX_CANARY: &str = "use-application-dns.net";
/// A tunnel earlier in a rule's order takes the rule back once it has
/// carried this long: its fresh checks are over.
pub const RETURN: Duration = Duration::from_mins(2);

#[derive(Debug, PartialEq, Eq)]
pub enum Plan<'a> {
    /// Answered here with this code and no records.
    Reply(ResponseCode),
    Network,
    /// A listed name and the lists that have it.
    Listed(Vec<&'a str>),
}

pub fn plan<'a>(lists: &'a Lists, name: &str) -> Plan<'a> {
    if normalize(name) == FIREFOX_CANARY {
        return Plan::Reply(ResponseCode::NXDomain);
    }
    let found = lists.match_domain(name);
    if found.is_empty() {
        Plan::Network
    } else {
        Plan::Listed(found)
    }
}

/// IPv6 is not routed, and HTTPS/SVCB carry address hints that would lead
/// the client past the route.
fn refused_type(qtype: RecordType) -> bool {
    matches!(
        qtype,
        RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
    )
}

/// An address that may get a route into a tunnel. A tunnel server is never
/// one: its own packets would loop into the tunnel.
pub fn routable(ip: Ipv4Addr, endpoints: &[Ipv4Addr]) -> bool {
    !endpoints.contains(&ip) && !SPECIAL.iter().any(|s| s.contains(ip))
}

pub fn ipv4_answers(msg: &Message) -> Vec<Ipv4Addr> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect()
}

pub fn has_fakeip(msg: &Message) -> bool {
    ipv4_answers(msg).into_iter().any(|ip| FAKEIP.contains(ip))
}

/// An answer with no records, for the question of `req`.
pub fn reply(req: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut msg = Message::new(req.metadata.id, MessageType::Response, req.metadata.op_code);
    msg.metadata.recursion_desired = req.metadata.recursion_desired;
    msg.metadata.recursion_available = true;
    msg.metadata.response_code = code;
    msg.queries.clone_from(&req.queries);
    msg.to_vec().ok()
}

/// Repeats of one kind of event are counted, not written, for this long
/// after the first: a network change fails hundreds of queries at once.
const BURST: Duration = Duration::from_secs(10);

/// Timestamped event lines: "<unix microseconds> <event>".
pub struct Journal {
    out: Mutex<Box<dyn Write + Send>>,
    /// Kind of event to the end of its burst and the repeats counted in it.
    bursts: Mutex<HashMap<&'static str, (Instant, u64)>>,
}

impl Journal {
    pub fn open(path: Option<&Path>) -> io::Result<Self> {
        let out: Box<dyn Write + Send> = match path {
            // It names every listed domain asked: not for other users.
            Some(p) => Box::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(p)?,
            ),
            None => Box::new(io::stderr()),
        };
        Ok(Self {
            out: Mutex::new(out),
            bursts: Mutex::new(HashMap::new()),
        })
    }

    /// Writes the event when it starts a burst of its kind, else counts it.
    pub fn burst(&self, kind: &'static str, event: fmt::Arguments<'_>) {
        let now = Instant::now();
        let over = match self.bursts.lock() {
            Ok(mut b) => match b.get_mut(kind) {
                Some((until, n)) if now < *until => {
                    *n += 1;
                    return;
                }
                _ => b.insert(kind, (now + BURST, 0)),
            },
            Err(_) => None,
        };
        if let Some((_, n)) = over {
            self.repeated(kind, n);
        }
        self.log(event);
    }

    /// Writes the counts of the bursts that are over.
    pub fn flush(&self) {
        let now = Instant::now();
        let mut over = Vec::new();
        if let Ok(mut b) = self.bursts.lock() {
            b.retain(|kind, &mut (until, n)| {
                let done = now >= until;
                if done {
                    over.push((*kind, n));
                }
                !done
            });
        }
        for (kind, n) in over {
            self.repeated(kind, n);
        }
    }

    fn repeated(&self, kind: &str, n: u64) {
        if n > 0 {
            self.log(format_args!(
                "{kind} repeated {n} more times within {}s",
                BURST.as_secs()
            ));
        }
    }

    pub fn log(&self, event: fmt::Arguments<'_>) {
        let us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_micros());
        if let Ok(mut out) = self.out.lock() {
            let _ = writeln!(out, "{us} {event}");
            let _ = out.flush();
        }
    }
}

/// What happened to a batch of routes placed on a tunnel interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Moves {
    pub added: usize,
    /// The route was there already and now points at the tunnel.
    pub moved: usize,
    pub removed: usize,
    pub failed: usize,
}

impl Moves {
    fn count(&mut self, r: &io::Result<Outcome>) {
        match r {
            Ok(Outcome::Added) => self.added += 1,
            Ok(_) => self.moved += 1,
            Err(_) => self.failed += 1,
        }
    }

    fn any(&self) -> bool {
        self.added + self.moved + self.removed + self.failed > 0
    }
}

impl fmt::Display for Moves {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "added={} moved={} removed={} failed={}",
            self.added, self.moved, self.removed, self.failed
        )
    }
}

/// A tunnel interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub index: u16,
}

/// What the checks of a link say of its tunnel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Health {
    /// Not confirmed yet, or failed.
    #[default]
    Down,
    /// The last confirmation or check went through.
    Up,
    /// A check found silent the ping that used to answer; TLS is to tell.
    Suspect,
    /// No probe gets through, yet the peer still answers: the tunnel keeps
    /// the names and the routes it has, so the network limps on through
    /// it, but a rule with another tunnel takes that one.
    Degraded,
}

impl Health {
    /// The tunnel is not to be walked away from: its names are answered
    /// and its routes stand.
    pub fn alive(self) -> bool {
        self != Self::Down
    }
}

/// A tunnel as its link reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkState {
    pub iface: Option<Iface>,
    /// Which amneziawg-go has the interface: a new one may get the name and
    /// index of a dead one, whose routes went with it.
    pub generation: u32,
    pub health: Health,
    /// A new network or a wake, until the first check after it.
    pub works: bool,
    /// Carrying without doubt since then.
    pub since: Option<Instant>,
    pub endpoint: Option<Ipv4Addr>,
}

impl LinkState {
    /// Carries for certain: a rule may switch to it.
    fn good(&self) -> bool {
        self.iface.is_some() && self.health == Health::Up
    }
}

/// Why the names of a rule are refused now; none of them, and they are not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reasons {
    /// No tunnel of the rule carries.
    pub tunnel: bool,
    /// A new network or a wake, until the first check of its tunnel.
    pub works: bool,
    pub owner: bool,
}

impl Reasons {
    pub fn any(self) -> bool {
        self.tunnel || self.works || self.owner
    }
}

impl fmt::Display for Reasons {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let on: Vec<&str> = [
            (self.tunnel, "tunnel"),
            (self.works, "works"),
            (self.owner, "owner"),
        ]
        .into_iter()
        .filter_map(|(set, name)| set.then_some(name))
        .collect();
        if on.is_empty() {
            f.write_str("off")
        } else {
            write!(f, "on {}", on.join(","))
        }
    }
}

/// The tunnel a rule takes now: the one it has while that carries, but a
/// tunnel earlier in its order once that has carried for `RETURN`; when it
/// does not carry, the first that does. A tunnel just after a new network
/// or a wake is waited for, not left. With none carrying, the rule stays
/// where it is, or takes the first tunnel that has an interface at all.
fn pick(
    order: &[usize],
    links: &[LinkState],
    current: Option<usize>,
    now: Instant,
) -> Option<usize> {
    let link = |t: usize| links.get(t);
    let good = |t: usize| link(t).is_some_and(|l| l.good() && !l.works);
    let settled = |t: usize| {
        good(t)
            && link(t)
                .and_then(|l| l.since)
                .is_some_and(|s| now.duration_since(s) >= RETURN)
    };
    let has_iface = |t: usize| link(t).is_some_and(|l| l.iface.is_some());
    if let Some(c) = current {
        if link(c).is_some_and(|l| l.works && l.iface.is_some()) {
            return Some(c);
        }
        if good(c) {
            return order
                .iter()
                .copied()
                .take_while(|&t| t != c)
                .find(|&t| settled(t))
                .or(Some(c));
        }
    }
    order
        .iter()
        .copied()
        .find(|&t| good(t))
        .or_else(|| current.filter(|&c| has_iface(c)))
        .or_else(|| order.iter().copied().find(|&t| has_iface(t)))
}

struct RuleRun {
    name: String,
    when: When,
    lists: Vec<String>,
    /// Indices of links, in the order of priority.
    tunnels: Vec<usize>,
    /// Its condition holds.
    active: bool,
    /// The link its routes point at.
    current: Option<usize>,
}

/// Where a route points: the link and its generation.
type Placed = (usize, u32);

struct HostRun {
    rule: usize,
    /// Unix seconds of the last answer that carried the address.
    last: u64,
    placed: Option<Placed>,
}

/// A route target: the link, its generation, its interface index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    link: usize,
    generation: u32,
    index: u16,
}

impl Target {
    fn placed(self) -> Placed {
        (self.link, self.generation)
    }
}

#[derive(Default)]
struct Core {
    links: Vec<(String, LinkState)>,
    rules: Vec<RuleRun>,
    hosts: HashMap<Ipv4Addr, HostRun>,
    /// Subnet routes in place: the rule that owns each, and where.
    subnets: HashMap<Subnet, (usize, Placed)>,
    /// Subnets passed over for holding a server or the fake range, as the
    /// journal was told.
    unrouted: HashSet<Subnet>,
    owner: bool,
    use_fakeip: bool,
    /// Every route was taken back: nothing is placed any more.
    stopped: bool,
}

impl Core {
    fn states(&self) -> Vec<LinkState> {
        self.links.iter().map(|(_, l)| l.clone()).collect()
    }

    fn current(&self, rule: usize) -> Option<&LinkState> {
        let r = self.rules.get(rule)?;
        self.links.get(r.current?).map(|(_, l)| l)
    }

    fn target(&self, rule: usize) -> Option<Target> {
        let r = self.rules.get(rule)?;
        let link = r.current?;
        let l = &self.links.get(link)?.1;
        let iface = l.iface.as_ref()?;
        Some(Target {
            link,
            generation: l.generation,
            index: iface.index,
        })
    }

    fn reasons(&self, rule: usize) -> Reasons {
        let l = self.current(rule);
        Reasons {
            tunnel: !l.is_some_and(|l| l.iface.is_some() && l.health.alive()),
            works: l.is_some_and(|l| l.works),
            owner: self.owner,
        }
    }

    fn carries(&self, rule: usize) -> bool {
        self.rules.get(rule).is_some_and(|r| r.active) && !self.reasons(rule).any()
    }

    fn endpoints(&self) -> Vec<Ipv4Addr> {
        self.links.iter().filter_map(|(_, l)| l.endpoint).collect()
    }

    /// Each list to the first rule in force that has it.
    fn owners(&self) -> HashMap<&str, usize> {
        let mut owners = HashMap::new();
        for (i, r) in self.rules.iter().enumerate().filter(|(_, r)| r.active) {
            for l in &r.lists {
                owners.entry(l.as_str()).or_insert(i);
            }
        }
        owners
    }

    /// Each subnet of the lists to the first rule in force that has it;
    /// the fake range is never anyone's.
    fn subnet_owners(&self, lists: &Lists) -> HashMap<Subnet, usize> {
        let owners = self.owners();
        let mut out: HashMap<Subnet, usize> = HashMap::new();
        for (s, list) in lists.subnets() {
            if s.overlaps(FAKEIP) {
                continue;
            }
            if let Some(&r) = owners.get(list) {
                out.entry(s).and_modify(|o| *o = (*o).min(r)).or_insert(r);
            }
        }
        out
    }

    /// The rule for a name in `lists`: the first in force whose tunnel
    /// carries; with none, the first in force, which refuses. None when no
    /// rule in force has the name.
    fn choose(&self, lists: &[&str]) -> Option<Pick> {
        let mut first = None;
        for (i, r) in self.rules.iter().enumerate() {
            if !r.active || !r.lists.iter().any(|l| lists.contains(&l.as_str())) {
                continue;
            }
            let pick = Pick {
                rule: i,
                name: r.name.clone(),
                always: r.when == When::Always,
                via: None,
                reasons: self.reasons(i),
            };
            if self.carries(i)
                && let Some(t) = self.target(i)
            {
                return Some(Pick {
                    via: Some(t.index),
                    ..pick
                });
            }
            first.get_or_insert(pick);
        }
        first
    }
}

/// The rule a query goes by, and its tunnel interface when it carries.
struct Pick {
    rule: usize,
    name: String,
    always: bool,
    via: Option<u16>,
    reasons: Reasons,
}

pub struct Resolver {
    /// Replaced whole when a source changes; a query keeps the lists it
    /// started with.
    lists: RwLock<Arc<Lists>>,
    pub limit: Duration,
    pub routes: RouteSocket,
    pub journal: Journal,
    /// The kill switch in pf; none for the resolver alone.
    pub pf: Option<Pf>,
    /// The tables in pf may lack an address or hold a stale one: reload
    /// them whole.
    pf_stale: AtomicBool,
    /// What pf holds now; none when unknown, so that it is loaded anew.
    pf_shape: tokio::sync::Mutex<Option<Shape>>,
    tunnel_dns: Ipv4Addr,
    upstream: Mutex<Option<Upstream>>,
    /// The physical interface and the network DNS, for pf.
    network: Mutex<Option<(String, Ipv4Addr)>>,
    core: Mutex<Core>,
    /// Hosts changed since the last save.
    dirty: AtomicBool,
}

impl Resolver {
    /// The rules as the settings give them, over the links named in order.
    pub fn new(
        lists: Lists,
        rules: &[config::Rule],
        links: Vec<String>,
        tunnel_dns: Ipv4Addr,
        routes: RouteSocket,
        journal: Journal,
        pf: Option<Pf>,
    ) -> Self {
        let core = Core {
            links: links
                .into_iter()
                .map(|n| (n, LinkState::default()))
                .collect(),
            rules: rules
                .iter()
                .map(|r| RuleRun {
                    name: r.name.clone(),
                    when: r.when.clone(),
                    lists: r.lists.clone(),
                    tunnels: r.tunnels.clone(),
                    active: false,
                    current: None,
                })
                .collect(),
            ..Core::default()
        };
        Self {
            lists: RwLock::new(Arc::new(lists)),
            limit: crate::LIMIT,
            routes,
            journal,
            pf,
            pf_stale: AtomicBool::new(true),
            pf_shape: tokio::sync::Mutex::new(None),
            tunnel_dns,
            upstream: Mutex::new(None),
            network: Mutex::new(None),
            core: Mutex::new(core),
            dirty: AtomicBool::new(false),
        }
    }

    fn core(&self) -> MutexGuard<'_, Core> {
        self.core
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn lists(&self) -> Arc<Lists> {
        self.lists
            .read()
            .map(|l| Arc::clone(&l))
            .unwrap_or_default()
    }

    /// Puts new lists in place; the next reconcile routes the new subnets
    /// and takes away the gone. Host routes of names no longer listed live
    /// out their window.
    pub fn set_lists(&self, lists: Lists) {
        if let Ok(mut l) = self.lists.write() {
            *l = Arc::new(lists);
        }
        self.pf_stale.store(true, Relaxed);
    }

    pub fn set_network(&self, n: Option<&Network>) {
        self.set_upstream(n.map(Network::upstream));
        if let Ok(mut net) = self.network.lock() {
            *net = n.map(|n| (n.iface.clone(), n.dns));
        }
    }

    /// The network DNS alone, for a resolver without pf.
    pub fn set_upstream(&self, up: Option<Upstream>) {
        if let Ok(mut u) = self.upstream.lock() {
            *u = up;
        }
    }

    fn upstream(&self) -> Option<Upstream> {
        self.upstream.lock().ok().and_then(|n| *n)
    }

    pub fn set_use_fakeip(&self, on: bool) {
        self.core().use_fakeip = on;
    }

    pub fn use_fakeip(&self) -> bool {
        self.core().use_fakeip
    }

    pub fn set_owner(&self, on: bool) {
        self.core().owner = on;
    }

    /// Rules in force by the country; the names of those that changed, and
    /// whether they came into force.
    pub fn set_country(&self, country: &str) -> Vec<(String, bool)> {
        let mut core = self.core();
        let mut changed = Vec::new();
        for r in &mut core.rules {
            let active = r.when.holds(country);
            if active != r.active {
                r.active = active;
                changed.push((r.name.clone(), active));
            }
        }
        if !changed.is_empty() {
            self.pf_stale.store(true, Relaxed);
        }
        changed
    }

    /// Which links a rule in force needs.
    pub fn wanted(&self) -> Vec<bool> {
        let core = self.core();
        (0..core.links.len())
            .map(|t| {
                core.rules
                    .iter()
                    .any(|r| r.active && r.tunnels.contains(&t))
            })
            .collect()
    }

    pub fn set_link(&self, link: usize, state: LinkState) {
        if let Some((_, l)) = self.core().links.get_mut(link) {
            *l = state;
        }
    }

    pub fn endpoints(&self) -> Vec<Ipv4Addr> {
        self.core().endpoints()
    }

    /// The interface to fetch sources through: the tunnel of the first rule
    /// in force that carries.
    pub fn fetch_iface(&self) -> Option<String> {
        let core = self.core();
        (0..core.rules.len())
            .filter(|&r| core.carries(r))
            .find_map(|r| core.current(r)?.iface.as_ref().map(|i| i.name.clone()))
    }

    /// Every rule in force has a tunnel interface for its routes.
    pub fn all_routed(&self) -> bool {
        let core = self.core();
        (0..core.rules.len()).all(|r| !core.rules[r].active || core.target(r).is_some())
    }

    /// The reasons of every rule in force, by name.
    pub fn reasons(&self) -> Vec<(String, Reasons)> {
        let core = self.core();
        core.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.active)
            .map(|(i, r)| (r.name.clone(), core.reasons(i)))
            .collect()
    }

    /// The rules, the tunnels, the lists and the hosts, for the status
    /// line. The sizes of the lists belong here and not only in `start
    /// daemon`: lists that shrank to nothing are invisible in a line that
    /// says only how the tunnels are.
    pub fn status(&self) -> String {
        let lists = self.lists();
        let core = self.core();
        let rules: Vec<String> = core
            .rules
            .iter()
            .map(|r| {
                let at = match (r.active, r.current) {
                    (false, _) => "off",
                    (true, None) => "none",
                    (true, Some(t)) => core.links.get(t).map_or("?", |(n, _)| n.as_str()),
                };
                format!("{}={at}", r.name)
            })
            .collect();
        let links: Vec<String> = core
            .links
            .iter()
            .map(|(n, l)| {
                let state = match (&l.iface, l.health) {
                    (None, _) => "down".to_owned(),
                    (Some(i), Health::Down) => format!("{}#{}/dead", i.name, i.index),
                    (Some(i), Health::Up) => format!("{}#{}/alive", i.name, i.index),
                    (Some(i), Health::Suspect) => format!("{}#{}/suspect", i.name, i.index),
                    (Some(i), Health::Degraded) => format!("{}#{}/degraded", i.name, i.index),
                };
                format!("{n}={state}")
            })
            .collect();
        format!(
            "rules={} tunnels={} suffixes={} subnets={} hosts={} use_fakeip={} owner={}",
            rules.join(","),
            links.join(","),
            lists.suffix_count(),
            lists.subnets().count(),
            core.hosts.len(),
            core.use_fakeip,
            core.owner
        )
    }

    /// The answer bytes for one query, or None to drop it.
    pub async fn handle(&self, query: &[u8]) -> Option<Vec<u8>> {
        let req = Message::from_vec(query).ok()?;
        if req.metadata.message_type != MessageType::Query {
            return None;
        }
        let [q] = req.queries.as_slice() else {
            return self.forward(&req, query).await;
        };
        let name = normalize(&q.name().to_ascii());
        let qtype = q.query_type();
        let lists = self.lists();
        let pick = match plan(&lists, &name) {
            Plan::Reply(code) => return self.refuse(&req, &name, qtype, code),
            Plan::Network => None,
            Plan::Listed(found) => self.core().choose(&found),
        };
        match pick {
            // Lists of rules not in force go as if not listed.
            None => self.forward(&req, query).await,
            Some(_) if refused_type(qtype) => {
                self.refuse(&req, &name, qtype, ResponseCode::NoError)
            }
            Some(pick) => self.listed(&req, query, &name, pick).await,
        }
    }

    fn refuse(
        &self,
        req: &Message,
        name: &str,
        qtype: RecordType,
        code: ResponseCode,
    ) -> Option<Vec<u8>> {
        // Every AAAA and HTTPS query of a listed name: a line each was a
        // third of the journal.
        self.journal
            .burst("refuse", format_args!("refuse {name} {qtype} {code}"));
        reply(req, code)
    }

    async fn forward(&self, req: &Message, query: &[u8]) -> Option<Vec<u8>> {
        let Some(network) = self.upstream() else {
            self.journal
                .burst("network-fail", format_args!("network-fail no network"));
            return reply(req, ResponseCode::ServFail);
        };
        match network.exchange(query, self.limit).await {
            Ok(answer) => Some(answer),
            Err(e) => {
                self.journal
                    .burst("network-fail", format_args!("network-fail {e}"));
                reply(req, ResponseCode::ServFail)
            }
        }
    }

    async fn listed(&self, req: &Message, query: &[u8], name: &str, pick: Pick) -> Option<Vec<u8>> {
        let rule = pick.name.as_str();
        // A rule "always" goes past the router while its tunnel carries.
        let router_first = !(pick.always && pick.via.is_some());
        if router_first
            && self.use_fakeip()
            && let Some(network) = self.upstream()
            && let Ok(bytes) = network.exchange(query, self.limit).await
            && Message::from_vec(&bytes).is_ok_and(|m| has_fakeip(&m))
        {
            self.journal.log(format_args!("fakeip {name} {rule}"));
            return Some(bytes);
        }
        let Some(index) = pick.via else {
            self.journal.burst(
                "killswitch",
                format_args!("killswitch {name} {rule} {}", pick.reasons),
            );
            return reply(req, ResponseCode::ServFail);
        };
        let tunnel = Upstream {
            server: SocketAddrV4::new(self.tunnel_dns, 53),
            bound_if: NonZeroU32::new(u32::from(index)),
        };
        let bytes = match tunnel.exchange(query, self.limit).await {
            Ok(bytes) => bytes,
            Err(e) => {
                self.journal.burst(
                    "killswitch",
                    format_args!("killswitch {name} {rule} tunnel: {e}"),
                );
                return reply(req, ResponseCode::ServFail);
            }
        };
        let Ok(answer) = Message::from_vec(&bytes) else {
            self.journal
                .log(format_args!("killswitch {name} {rule} bad answer"));
            return reply(req, ResponseCode::ServFail);
        };
        let ips = ipv4_answers(&answer);
        let endpoints = self.endpoints();
        let mut new = Vec::new();
        for &ip in &ips {
            if !routable(ip, &endpoints) {
                self.journal.log(format_args!("unrouted {name} {ip}"));
                continue;
            }
            match self.route_host(ip, pick.rule) {
                Ok(true) => new.push(ip),
                Ok(false) => {}
                Err(e) => {
                    // Never hand out an address that would go past the tunnel.
                    self.journal
                        .log(format_args!("killswitch {name} {rule} route {ip}: {e}"));
                    return reply(req, ResponseCode::ServFail);
                }
            }
        }
        if let Some(pf) = &self.pf
            && let Err(e) = pf.add(pick.rule, &new).await
        {
            // Routed, but not held by the kill switch: not handed out.
            self.pf_stale.store(true, Relaxed);
            self.journal
                .log(format_args!("killswitch {name} {rule} pf: {e}"));
            return reply(req, ResponseCode::ServFail);
        }
        self.journal.log(format_args!(
            "answer {name} {rule} {} {ips:?}",
            answer.metadata.response_code
        ));
        Some(bytes)
    }

    /// Routes `ip` into the tunnel of `rule` as it is now and renews its
    /// window. An address a rule earlier in order holds and carries stays
    /// with it. A route this process placed is left as it is; any other is
    /// moved. True when the address is new to the table of the rule.
    fn route_host(&self, ip: Ipv4Addr, rule: usize) -> io::Result<bool> {
        let mut core = self.core();
        if core.stopped {
            return Err(io::Error::other("stopped"));
        }
        let now = state::now();
        let prior = core.hosts.get(&ip).map(|h| (h.rule, h.placed));
        if let Some((owner, _)) = prior
            && owner < rule
            && core.carries(owner)
        {
            if let Some(h) = core.hosts.get_mut(&ip) {
                h.last = now;
            }
            self.dirty.store(true, Relaxed);
            return Ok(false);
        }
        let Some(target) = core.target(rule) else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "no tunnel"));
        };
        let dst = Subnet::host(ip);
        // A known address is placed again, not taken on trust: the kernel
        // loses a route with the interface it points at, and the tunnel
        // itself may be none the wiser. Nothing else would notice - the
        // rules move routes only when their tunnel changes. The kernel
        // answers Existed when the route is there, so this costs one call.
        let outcome = self.routes.set(dst, target.index)?;
        core.hosts.insert(
            ip,
            HostRun {
                rule,
                last: now,
                placed: Some(target.placed()),
            },
        );
        self.dirty.store(true, Relaxed);
        let new_here = prior.is_none_or(|(owner, _)| owner != rule);
        if prior.is_some() && new_here {
            // Still in the table of the rule it had.
            self.pf_stale.store(true, Relaxed);
        }
        // A known address answered again: its answer line says it all.
        // A route that had to be put back says so by its outcome.
        if new_here || outcome != Outcome::Existed {
            self.journal.log(format_args!(
                "route {dst} {outcome:?} if={} gen={}",
                target.index, target.generation
            ));
        }
        Ok(new_here)
    }

    /// Takes in hosts from the state, not routed yet.
    pub fn load_hosts(&self, hosts: impl IntoIterator<Item = (Ipv4Addr, usize, u64)>) {
        let mut core = self.core();
        let rules = core.rules.len();
        for (ip, rule, last) in hosts {
            if rule < rules {
                core.hosts.entry(ip).or_insert(HostRun {
                    rule,
                    last,
                    placed: None,
                });
            }
        }
        self.pf_stale.store(true, Relaxed);
    }

    /// Brings the routes in line with the rules and tunnels as they are
    /// now: picks each rule's tunnel, routes its hosts and subnets there,
    /// drops the hosts of rules no longer in force. Only changes reach the
    /// kernel, and only changes are written.
    pub fn reconcile(&self) {
        let lists = self.lists();
        let mut core = self.core();
        if core.stopped {
            return;
        }
        self.pick_tunnels(&mut core);
        let (hosts, dropped) = self.place_hosts(&mut core);
        let subnets = self.place_subnets(&mut core, &lists);
        for (i, r) in core.rules.iter().enumerate() {
            let (h, s, d) = (hosts[i], subnets[i], dropped[i]);
            if h.any() || s.any() || d > 0 {
                self.journal.log(format_args!(
                    "routes {} hosts {h} dropped={d} subnets {s}",
                    r.name
                ));
            }
        }
    }

    /// Each rule in force to its tunnel of now; a change is written.
    fn pick_tunnels(&self, core: &mut Core) {
        let now = Instant::now();
        let links = core.states();
        let mut events = Vec::new();
        for r in &mut core.rules {
            let new = if r.active {
                pick(&r.tunnels, &links, r.current, now)
            } else {
                None
            };
            if new != r.current {
                events.push((r.name.clone(), r.current, new));
                r.current = new;
            }
        }
        let name = |t: Option<usize>| {
            t.and_then(|t| core.links.get(t))
                .map_or("none", |(n, _)| n.as_str())
        };
        for (rule, from, to) in &events {
            self.journal.log(format_args!(
                "rule {rule} tunnel {} -> {}",
                name(*from),
                name(*to)
            ));
        }
    }

    /// Hosts to the tunnels of their rules; those of rules out of force,
    /// and tunnel servers, dropped. The moves and the drops, by rule.
    fn place_hosts(&self, core: &mut Core) -> (Vec<Moves>, Vec<usize>) {
        let rules = core.rules.len();
        let active: Vec<bool> = core.rules.iter().map(|r| r.active).collect();
        let targets: Vec<Option<Target>> = (0..rules).map(|r| core.target(r)).collect();
        let endpoints = core.endpoints();
        let mut moves = vec![Moves::default(); rules];
        let mut dropped = Vec::new();
        for (&ip, h) in &mut core.hosts {
            let keep = active.get(h.rule).copied().unwrap_or(false) && routable(ip, &endpoints);
            if !keep {
                if h.placed.is_some() {
                    let _ = self.routes.delete(Subnet::host(ip));
                }
                dropped.push((ip, h.rule));
                continue;
            }
            let Some(t) = targets.get(h.rule).copied().flatten() else {
                continue;
            };
            if h.placed != Some(t.placed()) {
                let r = self.routes.set(Subnet::host(ip), t.index);
                if let Some(m) = moves.get_mut(h.rule) {
                    m.count(&r);
                }
                match r {
                    Ok(_) => h.placed = Some(t.placed()),
                    Err(e) => self
                        .journal
                        .burst("route-fail", format_args!("route-fail {ip}: {e}")),
                }
            }
        }
        let mut by_rule = vec![0usize; rules];
        for (ip, rule) in &dropped {
            core.hosts.remove(ip);
            if let Some(n) = by_rule.get_mut(*rule) {
                *n += 1;
            }
        }
        if !dropped.is_empty() {
            self.dirty.store(true, Relaxed);
            self.pf_stale.store(true, Relaxed);
        }
        (moves, by_rule)
    }

    /// Subnets to the tunnel of the first rule in force that has them; with
    /// fake addresses upstream and that tunnel not carrying, to the router.
    /// A subnet that holds a tunnel server is not routed. The moves, by rule.
    fn place_subnets(&self, core: &mut Core, lists: &Lists) -> Vec<Moves> {
        let rules = core.rules.len();
        let endpoints = core.endpoints();
        let placeable: Vec<Option<Target>> = (0..rules)
            .map(|r| {
                let to_router = core.use_fakeip && core.reasons(r).tunnel;
                core.target(r).filter(|_| !to_router)
            })
            .collect();
        let mut want: HashMap<Subnet, (usize, Target)> = HashMap::new();
        let mut skipped = HashSet::new();
        for (s, r) in core.subnet_owners(lists) {
            if endpoints.iter().any(|&e| s.contains(e)) {
                skipped.insert(s);
                continue;
            }
            if let Some(t) = placeable.get(r).copied().flatten() {
                want.insert(s, (r, t));
            }
        }
        for s in skipped.difference(&core.unrouted) {
            self.journal.log(format_args!("unrouted {s}"));
        }
        core.unrouted = skipped;
        let mut moves = vec![Moves::default(); rules];
        let gone: Vec<(Subnet, usize)> = core
            .subnets
            .iter()
            .filter(|(s, (r, p))| {
                want.get(s)
                    .is_none_or(|(wr, wt)| wr != r || wt.placed() != *p)
            })
            .map(|(s, (r, _))| (*s, *r))
            .collect();
        for (s, r) in gone {
            core.subnets.remove(&s);
            if !want.contains_key(&s)
                && self.routes.delete(s).unwrap_or(false)
                && let Some(m) = moves.get_mut(r)
            {
                m.removed += 1;
            }
        }
        for (s, (r, t)) in want {
            if core.subnets.contains_key(&s) {
                continue;
            }
            let res = self.routes.set(s, t.index);
            if let Some(m) = moves.get_mut(r) {
                m.count(&res);
            }
            match res {
                Ok(_) => {
                    core.subnets.insert(s, (r, t.placed()));
                }
                Err(e) => self
                    .journal
                    .burst("route-fail", format_args!("route-fail {s}: {e}")),
            }
        }
        moves
    }

    /// Removes every route, for good; the hosts stay, to be saved. Returns
    /// how many routes were there to remove.
    pub fn remove_all(&self) -> usize {
        let mut core = self.core();
        core.stopped = true;
        let mut placed: Vec<Subnet> = core
            .hosts
            .iter_mut()
            .filter_map(|(ip, h)| h.placed.take().map(|_| Subnet::host(*ip)))
            .collect();
        placed.extend(core.subnets.drain().map(|(s, _)| s));
        placed
            .into_iter()
            .filter(|&d| self.routes.delete(d).unwrap_or(false))
            .count()
    }

    /// Drops hosts whose last answer is older than `window` seconds, routes
    /// and kill switch entries included; returns how many.
    pub async fn expire(&self, now: u64, window: u64) -> usize {
        let gone: Vec<(Ipv4Addr, HostRun)> = {
            let mut core = self.core();
            let old: Vec<Ipv4Addr> = core
                .hosts
                .iter()
                .filter(|(_, h)| now.saturating_sub(h.last) > window)
                .map(|(ip, _)| *ip)
                .collect();
            old.into_iter()
                .filter_map(|ip| core.hosts.remove(&ip).map(|h| (ip, h)))
                .collect()
        };
        if gone.is_empty() {
            return 0;
        }
        self.dirty.store(true, Relaxed);
        let mut by_rule: HashMap<usize, Vec<Ipv4Addr>> = HashMap::new();
        for (ip, h) in &gone {
            if h.placed.is_some() {
                let _ = self.routes.delete(Subnet::host(*ip));
            }
            by_rule.entry(h.rule).or_default().push(*ip);
        }
        if let Some(pf) = &self.pf {
            for (rule, ips) in by_rule {
                if let Err(e) = pf.delete(rule, &ips).await {
                    self.journal.log(format_args!("pf-fail delete: {e}"));
                    self.pf_stale.store(true, Relaxed);
                }
            }
        }
        gone.len()
    }

    fn shape(&self) -> Shape {
        let core = self.core();
        let rules = core
            .rules
            .iter()
            .map(|r| {
                r.active.then(|| {
                    r.tunnels
                        .iter()
                        .filter_map(|&t| core.links.get(t)?.1.iface.as_ref())
                        .map(|i| i.name.clone())
                        .collect()
                })
            })
            .collect();
        Shape {
            rules,
            use_fakeip: core.use_fakeip,
            endpoints: core.endpoints(),
            network: self.network.lock().ok().and_then(|n| n.clone()),
        }
    }

    /// The tables of the rules: every host by its rule, and the subnets of
    /// each rule in force but the fake range. A subnet that holds a tunnel
    /// server is not routed, yet held: only the server itself is let out
    /// past the tunnel.
    fn tables(&self) -> Tables {
        let lists = self.lists();
        let core = self.core();
        let rules = core.rules.len();
        let mut hosts = vec![Vec::new(); rules];
        for (ip, h) in &core.hosts {
            if let Some(t) = hosts.get_mut(h.rule) {
                t.push(*ip);
            }
        }
        let mut nets = vec![Vec::new(); rules];
        for (s, r) in core.subnet_owners(&lists) {
            if let Some(t) = nets.get_mut(r) {
                t.push(s);
            }
        }
        for t in &mut hosts {
            t.sort();
        }
        for t in &mut nets {
            t.sort_by_key(|s| (s.addr, s.prefix));
        }
        Tables { hosts, nets }
    }

    /// Reloads pf when what it depends on changed, or its tables may be
    /// out of date. Written to the journal either way.
    pub async fn sync_pf(&self) -> io::Result<()> {
        let Some(pf) = &self.pf else {
            return Ok(());
        };
        let mut last = self.pf_shape.lock().await;
        let shape = self.shape();
        let stale = self.pf_stale.swap(false, Relaxed);
        if !stale && last.as_ref() == Some(&shape) {
            return Ok(());
        }
        match pf.load(&shape, || self.tables()).await {
            Ok(()) => {
                self.journal.log(format_args!("pf {shape}"));
                *last = Some(shape);
                Ok(())
            }
            Err(e) => {
                self.journal.burst("pf-fail", format_args!("pf-fail {e}"));
                self.pf_stale.store(true, Relaxed);
                *last = None;
                Err(e)
            }
        }
    }

    /// True when `ip` is routed into a tunnel by a host route or a subnet.
    pub fn covers(&self, ip: Ipv4Addr) -> bool {
        let core = self.core();
        core.hosts.get(&ip).is_some_and(|h| h.placed.is_some())
            || core.subnets.keys().any(|n| n.contains(ip))
    }

    /// True when pf may hold `ip` back: a host or a subnet of a rule in
    /// force.
    pub fn held(&self, ip: Ipv4Addr) -> bool {
        let lists = self.lists();
        let core = self.core();
        core.hosts.contains_key(&ip) || core.subnet_owners(&lists).keys().any(|s| s.contains(ip))
    }

    /// The hosts with the names of their rules, to be saved.
    pub fn hosts_snapshot(&self) -> Hosts {
        let core = self.core();
        core.hosts
            .iter()
            .filter_map(|(ip, h)| {
                let rule = core.rules.get(h.rule)?.name.clone();
                Some((*ip, Host { rule, last: h.last }))
            })
            .collect()
    }

    pub fn host_count(&self) -> usize {
        self.core().hosts.len()
    }

    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Relaxed)
    }

    pub fn mark_dirty(&self) {
        self.dirty.store(true, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record};

    fn lists() -> Lists {
        let mut l = Lists::default();
        l.add("custom", "example.com\n");
        l
    }

    #[test]
    fn plans() {
        let l = lists();
        assert_eq!(plan(&l, "www.example.com."), Plan::Listed(vec!["custom"]));
        assert_eq!(plan(&l, "other.org"), Plan::Network);
        assert_eq!(
            plan(&l, "Use-Application-DNS.net."),
            Plan::Reply(ResponseCode::NXDomain)
        );
        assert!(refused_type(RecordType::AAAA));
        assert!(refused_type(RecordType::HTTPS));
        assert!(!refused_type(RecordType::A));
        assert!(!refused_type(RecordType::MX));
    }

    #[test]
    fn routable_addresses() {
        let server = Ipv4Addr::new(203, 0, 113, 7);
        assert!(routable(Ipv4Addr::new(149, 154, 167, 99), &[server]));
        assert!(!routable(server, &[server]));
        assert!(!routable(server, &[Ipv4Addr::new(1, 1, 1, 1), server]));
        assert!(routable(server, &[]));
        for ip in [
            "0.0.0.0",
            "10.7.0.2",
            "100.64.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.20.10.1",
            "192.168.1.1",
            "224.0.0.251",
            "255.255.255.255",
            "198.18.0.5",
            "198.19.1.1",
        ] {
            assert!(!routable(ip.parse().unwrap(), &[]), "{ip}");
        }
        assert!(routable(Ipv4Addr::new(198, 20, 0, 1), &[]));
    }

    fn link(index: u16, alive: bool, since: Option<Instant>) -> LinkState {
        LinkState {
            iface: Some(Iface {
                name: format!("utun{index}"),
                index,
            }),
            generation: u32::from(index),
            health: if alive { Health::Up } else { Health::Down },
            since,
            ..LinkState::default()
        }
    }

    #[test]
    fn picks_the_first_that_carries_and_returns_after_a_while() {
        let now = Instant::now();
        let long = Some(now.checked_sub(RETURN).unwrap());
        let order = [0, 1];
        let both = [link(4, true, long), link(5, true, long)];
        assert_eq!(pick(&order, &both, None, now), Some(0));
        assert_eq!(pick(&order, &both, Some(0), now), Some(0));
        // Back to the first once it has stood.
        assert_eq!(pick(&order, &both, Some(1), now), Some(0));
        // Not before.
        let fresh = [link(4, true, Some(now)), link(5, true, long)];
        assert_eq!(pick(&order, &fresh, Some(1), now), Some(1));
        // The first dead: the second.
        let dead = [link(4, false, None), link(5, true, long)];
        assert_eq!(pick(&order, &dead, Some(0), now), Some(1));
        // Suspect: the second, if it carries.
        let mut suspect = [link(4, true, long), link(5, true, long)];
        suspect[0].health = Health::Suspect;
        assert_eq!(pick(&order, &suspect, Some(0), now), Some(1));
        suspect[1].health = Health::Down;
        assert_eq!(pick(&order, &suspect, Some(0), now), Some(0));
        // Degraded: the same, and it keeps its names and routes meanwhile.
        let mut degraded = [link(4, true, long), link(5, true, long)];
        degraded[0].health = Health::Degraded;
        assert_eq!(pick(&order, &degraded, Some(0), now), Some(1));
        assert!(degraded[0].health.alive());
        degraded[1].health = Health::Down;
        assert_eq!(pick(&order, &degraded, Some(0), now), Some(0));
        // None carries: stays; nothing yet: the first with an interface.
        let none = [link(4, false, None), link(5, false, None)];
        assert_eq!(pick(&order, &none, Some(1), now), Some(1));
        assert_eq!(pick(&order, &none, None, now), Some(0));
        let mut gone = none.clone();
        gone[0].iface = None;
        assert_eq!(pick(&order, &gone, None, now), Some(1));
        gone[1].iface = None;
        assert_eq!(pick(&order, &gone, Some(1), now), None);
        // Just after a wake: waited for, not left.
        let mut woke = [link(4, true, long), link(5, true, long)];
        woke[0].works = true;
        assert_eq!(pick(&order, &woke, Some(0), now), Some(0));
    }

    fn resolver(rules: &str) -> Resolver {
        let s = config::parse(rules).unwrap();
        let mut l = Lists::default();
        l.add("custom", "example.com\n149.154.160.0/20\n");
        l.add("outside", "example.net\nexample.com\n");
        Resolver::new(
            l,
            &s.rules,
            s.tunnels.iter().map(|t| t.name.clone()).collect(),
            Ipv4Addr::new(1, 1, 1, 1),
            RouteSocket::open().unwrap(),
            Journal::open(None).unwrap(),
            None,
        )
    }

    const RULES: &str = r#"
[[list]]
name = "custom"
sources = ["c.lst"]
[[list]]
name = "outside"
sources = ["o.lst"]
[[tunnel]]
name = "main"
conf = "main.conf"
[[tunnel]]
name = "backup"
conf = "backup.conf"
[[tunnel]]
name = "other"
conf = "other.conf"
[[rule]]
name = "always"
when = "always"
lists = ["custom"]
tunnels = ["main", "backup"]
[[rule]]
name = "home"
when = "!DE"
lists = ["outside"]
tunnels = ["other"]
"#;

    #[test]
    fn rules_by_country_and_tunnel() {
        let r = resolver(RULES);
        assert_eq!(r.set_country("DE"), [("always".to_owned(), true)]);
        assert_eq!(r.wanted(), [true, true, false]);
        // Listed in both, "home" not in force: the first rule.
        let pick = r.core().choose(&["custom", "outside"]).unwrap();
        assert_eq!((pick.rule, pick.via), (0, None));
        assert!(pick.reasons.tunnel);
        // Only in "home", not in force: goes as if not listed.
        assert!(r.core().choose(&["outside"]).is_none());
        assert_eq!(r.set_country("FR"), [("home".to_owned(), true)]);
        assert_eq!(r.wanted(), [true, true, true]);
        r.set_link(2, link(9, true, Some(Instant::now())));
        {
            let mut core = r.core();
            core.rules[1].current = Some(2);
        }
        // "always" first by order, refusing; "home" carries and takes it.
        let pick = r.core().choose(&["custom", "outside"]).unwrap();
        assert_eq!((pick.rule, pick.via, pick.always), (1, Some(9), false));
        r.set_owner(true);
        let pick = r.core().choose(&["outside"]).unwrap();
        assert_eq!(pick.via, None);
        assert!(pick.reasons.owner);
        let status = r.status();
        assert!(
            status.starts_with(
                "rules=always=none,home=other tunnels=main=down,backup=down,other=utun9#9/alive"
            ),
            "{status}"
        );
    }

    #[test]
    fn subnets_go_to_the_first_rule_in_force() {
        let r =
            resolver(&RULES.replace("lists = [\"outside\"]", "lists = [\"outside\", \"custom\"]"));
        r.set_country("FR");
        let t = r.tables();
        let net: Subnet = Subnet {
            addr: Ipv4Addr::new(149, 154, 160, 0),
            prefix: 20,
        };
        assert_eq!(t.nets[0], [net]);
        assert!(t.nets[1].is_empty());
        let s = r.shape();
        assert_eq!(s.rules, [Some(Vec::new()), Some(Vec::new())]);
        r.set_country("DE");
        assert_eq!(r.shape().rules, [Some(Vec::new()), None]);
    }

    #[test]
    fn hosts_of_rules_out_of_force_are_dropped() {
        let r = resolver(RULES);
        r.set_country("FR");
        r.load_hosts([
            (Ipv4Addr::new(93, 184, 216, 34), 0, 100),
            (Ipv4Addr::new(213, 59, 254, 7), 1, 200),
            (Ipv4Addr::new(1, 2, 3, 4), 7, 200),
        ]);
        assert_eq!(r.host_count(), 2);
        let snap = r.hosts_snapshot();
        assert_eq!(snap[&Ipv4Addr::new(213, 59, 254, 7)].rule, "home");
        r.set_country("DE");
        r.reconcile();
        assert_eq!(r.host_count(), 1);
        assert_eq!(r.tables().hosts[0], [Ipv4Addr::new(93, 184, 216, 34)]);
    }

    fn answer(ips: &[Ipv4Addr]) -> Message {
        let mut m = Message::new(7, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("example.com.").unwrap();
        for &ip in ips {
            m.add_answer(Record::from_rdata(name.clone(), 60, RData::A(A(ip))));
        }
        m
    }

    #[test]
    fn fakeip_detection() {
        assert!(has_fakeip(&answer(&[Ipv4Addr::new(198, 18, 0, 15)])));
        assert!(has_fakeip(&answer(&[Ipv4Addr::new(198, 19, 255, 1)])));
        assert!(!has_fakeip(&answer(&[Ipv4Addr::new(198, 20, 0, 1)])));
        assert!(!has_fakeip(&answer(&[])));
        assert_eq!(
            ipv4_answers(&answer(&[
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(5, 6, 7, 8)
            ])),
            vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]
        );
    }

    #[test]
    fn bursts_are_counted() {
        let path = std::env::temp_dir().join(format!("mac-gate-journal-{}", std::process::id()));
        let j = Journal::open(Some(&path)).unwrap();
        for i in 0..5 {
            j.burst("network-fail", format_args!("network-fail {i}"));
        }
        j.burst("killswitch", format_args!("killswitch a"));
        j.flush();
        if let Ok(mut b) = j.bursts.lock() {
            for (until, _) in b.values_mut() {
                *until = Instant::now();
            }
        }
        j.flush();
        j.burst("network-fail", format_args!("network-fail again"));
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let events: Vec<&str> = text.lines().map(|l| l.split_once(' ').unwrap().1).collect();
        assert_eq!(
            events,
            vec![
                "network-fail 0",
                "killswitch a",
                "network-fail repeated 4 more times within 10s",
                "network-fail again",
            ]
        );
    }

    #[test]
    fn reasons_shown() {
        assert_eq!(Reasons::default().to_string(), "off");
        let r = Reasons {
            tunnel: true,
            works: false,
            owner: true,
        };
        assert_eq!(r.to_string(), "on tunnel,owner");
        assert!(r.any());
        assert!(!Reasons::default().any());
    }

    #[test]
    fn reply_keeps_id_and_question() {
        let mut req = Message::new(4242, MessageType::Query, OpCode::Query);
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
        ));
        let bytes = reply(&req, ResponseCode::NoError).unwrap();
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(msg.metadata.id, 4242);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.metadata.recursion_desired);
        assert_eq!(msg.queries, req.queries);
        assert!(msg.answers.is_empty());
    }
}
