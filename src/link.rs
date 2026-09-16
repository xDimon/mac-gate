//! One tunnel kept up: amneziawg-go started, confirmed and checked, and
//! replaced by a new one when it stops carrying. Each tunnel is a task of
//! its own, so that a slow probe of one never holds another back. What it
//! finds goes to the resolver, which moves the routes of the rules.
//!
//! Liveness is only real exchange through the tunnel: a ping to anycast
//! addresses, then TLS. A reconnect is a new amneziawg-go, so a new source
//! port; the new tunnel comes up first and takes the routes over, then the
//! old one goes.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::watch::Receiver;

use crate::net::{self, Network};
use crate::probe::{self, TARGETS};
use crate::resolver::{Iface, LinkState, Resolver};
use crate::tunnel::{Conf, Tools, Tunnel};

const TICK: Duration = Duration::from_secs(1);
/// A tunnel after connecting or waking is checked often: DPI cuts new flows
/// in their first seconds.
const FRESH: Duration = Duration::from_mins(2);
const FAST: Duration = Duration::from_secs(5);
const SLOW: Duration = Duration::from_secs(30);
/// A new tunnel must pass TLS within this, or it is replaced at once.
const CONFIRM: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(2);
/// The first check after a wake: a live tunnel answers well within it, and
/// a dead one should not hold the reconnect back with a TLS try.
const WAKE_PING: Duration = Duration::from_secs(1);
const TLS: Duration = Duration::from_secs(15);
/// A fresh tunnel that failed the ping gets a short TLS try: a cut in the
/// first seconds must end in a reconnect within 10 s.
const FRESH_TLS: Duration = Duration::from_secs(3);
const DIRECT_TLS: Duration = Duration::from_secs(5);
/// Connects in a row without a pause, then pauses of these seconds.
const FAST_TRIES: u32 = 5;
const PAUSES: [u64; 3] = [30, 60, 120];
/// The attempt count starts over once a tunnel has stood this long.
const STABLE: Duration = Duration::from_mins(2);
/// Sent within the window with nothing back: a cut flow, checked at once.
/// The counters are read every tick. Packets, not bytes: a connect that
/// gets no answer sends only its SYNs, a few dozen bytes each.
const CUT_WINDOW: Duration = Duration::from_secs(4);
const CUT_PACKETS: u64 = 3;

/// Numbers every amneziawg-go of every tunnel: its name file, and the
/// generation of its interface.
static SEQ: AtomicU32 = AtomicU32::new(0);

/// What the watch tells a link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ctl {
    /// A rule in force takes the tunnel.
    pub wanted: bool,
    /// Wakes counted: a new count is a new wake.
    pub wakes: u64,
    /// The daemon stops: down and out.
    pub stop: bool,
}

/// What the next check knows beforehand; both skip the TLS try.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Usual,
    /// The counters show a cut.
    Cut,
    /// The first check after a wake: a short ping.
    Woke,
}

/// What answered a check through the tunnel, and after how long.
enum Found {
    Ping(Duration),
    Tls(Duration),
}

/// What the checks say of the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Health {
    /// Not confirmed yet, or failed.
    Down,
    Up,
    /// Was up, but the ping that used to answer is silent; TLS is to tell.
    Suspect,
}

pub struct Link {
    id: usize,
    name: String,
    resolver: Arc<Resolver>,
    conf: Conf,
    tools: Tools,
    tunnel: Option<Tunnel>,
    generation: u32,
    /// Connects in a row that did not end in a confirmed tunnel.
    failures: u32,
    /// A connect is due at this time.
    connect_at: Option<Instant>,
    confirmed: Option<Instant>,
    fresh_until: Instant,
    check_at: Instant,
    /// Counters of the tunnel interface: when, packets received, sent.
    samples: VecDeque<(Instant, u64, u64)>,
    /// A cut the ping refuted is not suspected again before the next check:
    /// a program knocking on a dead address would raise it every window.
    cut_quiet_until: Instant,
    next: Next,
    offline: bool,
    network: Option<Network>,
    net: Receiver<Option<Network>>,
    ctl: Receiver<Ctl>,
    wakes: u64,
    /// An event whose recovery is timed, and when it was seen.
    pending: Option<(&'static str, Instant)>,
    /// A new network or a wake not yet checked, since when.
    works: Option<Instant>,
    health: Health,
    since: Option<Instant>,
    /// The ping has answered through this tunnel: its silence means
    /// something. Some servers never answer it.
    pinged: bool,
    endpoint: Option<Ipv4Addr>,
    /// What the resolver was told last.
    published: LinkState,
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl Link {
    pub fn new(
        id: usize,
        name: String,
        resolver: Arc<Resolver>,
        conf: Conf,
        tools: Tools,
        mut net: Receiver<Option<Network>>,
        ctl: Receiver<Ctl>,
    ) -> Self {
        let now = Instant::now();
        let network = net.borrow_and_update().clone();
        let wakes = ctl.borrow().wakes;
        // A server written as an address is let out from the start.
        let endpoint = conf.endpoint_ip();
        Self {
            id,
            name,
            resolver,
            conf,
            tools,
            tunnel: None,
            generation: 0,
            failures: 0,
            connect_at: Some(now),
            confirmed: None,
            fresh_until: now,
            check_at: now,
            samples: VecDeque::new(),
            cut_quiet_until: now,
            next: Next::Usual,
            offline: false,
            network,
            net,
            ctl,
            wakes,
            pending: Some(("start", now)),
            works: None,
            health: Health::Down,
            since: None,
            pinged: false,
            endpoint,
            published: LinkState::default(),
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                Ok(()) = self.net.changed() => {}
                Ok(()) = self.ctl.changed() => {}
            }
            if self.step().await {
                return;
            }
        }
    }

    fn log(&self, event: fmt::Arguments<'_>) {
        self.resolver
            .journal
            .log(format_args!("{}: {event}", self.name));
    }

    fn state(&self) -> LinkState {
        LinkState {
            iface: self.tunnel.as_ref().map(|t| Iface {
                name: t.name.clone(),
                index: t.index,
            }),
            generation: self.generation,
            alive: self.health != Health::Down,
            suspect: self.health == Health::Suspect,
            works: self.works.is_some(),
            since: self.since,
            endpoint: self.endpoint,
        }
    }

    /// Tells the resolver what changed, which then moves the routes of the
    /// rules and reloads pf.
    async fn sync(&mut self) {
        let state = self.state();
        if state == self.published {
            return;
        }
        self.published = state.clone();
        self.resolver.set_link(self.id, state);
        self.resolver.reconcile();
        let _ = self.resolver.sync_pf().await;
    }

    /// True when the link is done.
    async fn step(&mut self) -> bool {
        let ctl = *self.ctl.borrow_and_update();
        if ctl.stop {
            self.down("stop").await;
            return true;
        }
        let now = Instant::now();
        if ctl.wakes != self.wakes {
            self.wakes = ctl.wakes;
            self.woke(now);
        }
        let n = self.net.borrow_and_update().clone();
        if n != self.network {
            self.follow_network(n);
        }
        if !ctl.wanted {
            if self.tunnel.is_some() {
                self.down("no rule in force takes it").await;
            }
            self.connect_at = Some(Instant::now());
            self.failures = 0;
            self.works = None;
            self.sync().await;
            return false;
        }
        if self.tunnel.as_mut().is_some_and(Tunnel::exited) {
            // Nothing to hand over: the kernel drops the routes with the
            // interface, and a new tunnel may reuse its name.
            if let Some(dead) = self.tunnel.take() {
                dead.down().await;
            }
            if self.connect_at.is_none() {
                self.lost("process exited");
            }
            self.sync().await;
        }
        if self.connect_at.is_none()
            && self.next == Next::Usual
            && Instant::now() >= self.cut_quiet_until
            && self.cut_seen().await
        {
            self.log(format_args!(
                "cut suspected: sent without reply for {}s",
                CUT_WINDOW.as_secs()
            ));
            self.next = Next::Cut;
            self.check_at = Instant::now();
        }
        match self.connect_at {
            Some(at) if Instant::now() >= at => self.connect().await,
            None if Instant::now() >= self.check_at => self.check().await,
            _ => {}
        }
        self.sync().await;
        false
    }

    fn woke(&mut self, now: Instant) {
        self.fresh(now);
        self.next = Next::Woke;
        self.pending = Some(("wake", now));
        self.retry_now(now);
        self.works = Some(now);
    }

    fn follow_network(&mut self, n: Option<Network>) {
        self.network = n;
        let now = Instant::now();
        self.fresh(now);
        self.pending.get_or_insert(("network", now));
        if self.network.is_some() {
            self.retry_now(now);
        }
        self.works = Some(now);
    }

    /// A new network or a wake: a tunnel that is down is tried at once, with
    /// the fast attempts anew, instead of sitting out a pause earned elsewhere.
    fn retry_now(&mut self, now: Instant) {
        if self.connect_at.is_some() {
            self.failures = 0;
            self.connect_at = Some(now);
        }
    }

    fn fresh(&mut self, now: Instant) {
        self.fresh_until = now + FRESH;
        self.check_at = self.check_at.min(now);
    }

    /// Carries: from a doubt or a failure, its time to take a rule back
    /// starts now, and it is checked often meanwhile.
    fn healthy(&mut self, now: Instant) {
        if self.health != Health::Up || self.since.is_none() {
            self.since = Some(now);
            self.fresh(now);
            self.check_at = now + FAST;
        }
        self.health = Health::Up;
    }

    fn unhealthy(&mut self) {
        self.health = Health::Down;
        self.since = None;
    }

    fn lost(&mut self, reason: &str) {
        let now = Instant::now();
        self.log(format_args!("lost {reason}"));
        self.unhealthy();
        self.confirmed = None;
        self.connect_at = Some(now);
        self.pending.get_or_insert(("reconnect", now));
    }

    async fn down(&mut self, why: &str) {
        if let Some(t) = self.tunnel.take() {
            let shown = t.to_string();
            t.down().await;
            self.log(format_args!("down {shown}: {why}"));
        }
        self.unhealthy();
        self.confirmed = None;
        self.sync().await;
    }

    /// Runs a probe unless the network changes first; None when it did.
    async fn unless_moved<T>(&self, probe: impl Future<Output = T>) -> Option<T> {
        let mut net = self.net.clone();
        let moved = async move {
            if net.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            v = probe => Some(v),
            () = moved => None,
        }
    }

    /// Reads the tunnel counters; true when over the last window packets
    /// went out and none came back.
    async fn cut_seen(&mut self) -> bool {
        let Some(t) = &self.tunnel else {
            return false;
        };
        let Some(c) = probe::counters(&t.name).await else {
            return false;
        };
        let (rx, tx) = (c.rx_packets, c.tx_packets);
        let now = Instant::now();
        self.samples.push_back((now, rx, tx));
        // Keep the newest sample that is at least a window old, and after it.
        while self
            .samples
            .get(1)
            .is_some_and(|s| now.duration_since(s.0) >= CUT_WINDOW)
        {
            self.samples.pop_front();
        }
        let Some(&(at, rx0, tx0)) = self.samples.front() else {
            return false;
        };
        now.duration_since(at) >= CUT_WINDOW && rx == rx0 && tx.saturating_sub(tx0) >= CUT_PACKETS
    }

    async fn endpoint(&self) -> std::io::Result<Ipv4Addr> {
        if let Some(ip) = self.conf.endpoint_ip() {
            return Ok(ip);
        }
        let n = self
            .network
            .as_ref()
            .ok_or_else(|| std::io::Error::other("no network"))?;
        net::resolve_ipv4(n.upstream(), &self.conf.endpoint_host).await
    }

    async fn connect(&mut self) {
        self.generation = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
        self.log(format_args!("connect attempt={}", self.failures + 1));
        let start = Instant::now();
        let endpoint = match self.endpoint().await {
            Ok(ip) => ip,
            Err(e) => {
                self.log(format_args!("connect-fail endpoint: {e}"));
                self.failed();
                return;
            }
        };
        // The server is let out before the first packet to it.
        self.endpoint = Some(endpoint);
        self.sync().await;
        let new = match Tunnel::up(&self.tools, &self.conf, endpoint, self.generation).await {
            Ok(t) => t,
            Err(e) => {
                self.log(format_args!("connect-fail {e}"));
                self.failed();
                return;
            }
        };
        let port = new.listen_port(&self.tools).await;
        self.log(format_args!(
            "up {new} endpoint={endpoint} port={} in {}ms",
            port.map_or_else(|| "?".to_owned(), |p| p.to_string()),
            start.elapsed().as_millis()
        ));
        let name = new.name.clone();
        let old = self.tunnel.replace(new);
        self.unhealthy();
        self.pinged = false;
        // The routes go to the new interface, and pf lets them out through
        // it, before the old one goes.
        self.sync().await;
        if let Some(old) = old {
            let shown = old.to_string();
            old.down().await;
            self.log(format_args!("down {shown}"));
        }
        let start = Instant::now();
        match self.unless_moved(probe::tls(&name, CONFIRM)).await {
            Some(true) => {
                let now = Instant::now();
                self.log(format_args!(
                    "confirm {}ms",
                    now.duration_since(start).as_millis()
                ));
                self.connect_at = None;
                self.confirmed = Some(now);
                self.healthy(now);
                self.samples.clear();
                self.next = Next::Usual;
                self.offline = false;
                self.works = None;
                self.recovered(now);
            }
            Some(false) => {
                // No handshake: the packets are lost on the way; one and no
                // TLS: the data is.
                let seen = self.tunnel_seen().await;
                self.log(format_args!("confirm-fail {seen}"));
                self.failed();
            }
            None => {
                self.log(format_args!("confirm aborted: network changed"));
                // Not this tunnel's failure: the next one goes out on the
                // new network.
                self.connect_at = Some(Instant::now());
                let n = self.net.borrow_and_update().clone();
                self.follow_network(n);
            }
        }
    }

    /// The handshake and the counters of the tunnel, for the journal.
    async fn tunnel_seen(&self) -> String {
        let Some(t) = &self.tunnel else {
            return "no tunnel".to_owned();
        };
        let handshake = t
            .handshake_age(&self.tools)
            .await
            .map_or_else(|| "none".to_owned(), |s| format!("{s}s"));
        let counters = probe::counters(&t.name).await.map_or_else(
            || "?".to_owned(),
            |c| format!("rx={} tx={}", c.rx_bytes, c.tx_bytes),
        );
        format!("handshake={handshake} {counters}")
    }

    fn failed(&mut self) {
        self.unhealthy();
        self.failures += 1;
        let now = Instant::now();
        if self.failures < FAST_TRIES {
            self.connect_at = Some(now);
            return;
        }
        let i = usize::try_from(self.failures - FAST_TRIES).unwrap_or(usize::MAX);
        let secs = PAUSES.get(i).or(PAUSES.last()).copied().unwrap_or_default();
        self.log(format_args!("pause {secs}s"));
        self.connect_at = Some(now + Duration::from_secs(secs));
    }

    /// A probe was cut short by a network change: nothing learned about the
    /// tunnel, asked again on the new network.
    fn aborted(&mut self, next: Next) {
        self.log(format_args!("check aborted: network changed"));
        self.next = next;
        self.check_at = Instant::now();
        let n = self.net.borrow_and_update().clone();
        self.follow_network(n);
    }

    async fn check(&mut self) {
        let now = Instant::now();
        let fresh = now < self.fresh_until;
        self.check_at = now + if fresh { FAST } else { SLOW };
        let Some(t) = &self.tunnel else {
            self.works = None;
            self.lost("no tunnel");
            return;
        };
        let (name, index) = (t.name.clone(), t.index);
        let next = std::mem::replace(&mut self.next, Next::Usual);
        let (cut, woke) = (next == Next::Cut, next == Next::Woke);
        let (ping_limit, tls_limit) = if woke {
            (WAKE_PING, None)
        } else if fresh {
            (PING, Some(FRESH_TLS))
        } else {
            (PING, Some(TLS))
        };
        // The probe below gets replies or ends in a reconnect: a new window.
        self.samples.clear();
        let start = Instant::now();
        let bound = NonZeroU32::new(u32::from(index));
        let Some(rtt) = self
            .unless_moved(probe::ping(bound, &TARGETS, ping_limit))
            .await
        else {
            return self.aborted(next);
        };
        let found = match (rtt, tls_limit) {
            (Some(rtt), _) => {
                self.pinged = true;
                Some(Found::Ping(rtt))
            }
            (None, Some(limit)) if !cut => {
                if self.pinged && self.health == Health::Up {
                    // A rule may go to its next tunnel while TLS tells.
                    self.log(format_args!("suspect: ping failed, tls next"));
                    self.health = Health::Suspect;
                    self.since = None;
                    self.sync().await;
                }
                match self.unless_moved(probe::tls(&name, limit)).await {
                    None => return self.aborted(next),
                    Some(ok) => ok.then(|| Found::Tls(start.elapsed())),
                }
            }
            (None, _) => None,
        };
        // Whatever this check finds is a reason of its own, or none.
        self.works = None;
        if self.report(found.as_ref(), next) {
            if cut {
                self.cut_quiet_until = self.check_at;
            }
            let now = Instant::now();
            self.healthy(now);
            if self.offline {
                self.offline = false;
                self.log(format_args!("online"));
            }
            if self.failures > 0 && self.confirmed.is_some_and(|c| c.elapsed() >= STABLE) {
                self.failures = 0;
                self.log(format_args!("stable"));
            }
            self.recovered(now);
            return;
        }
        self.unhealthy();
        // The rules leave it before the probe past the tunnel.
        self.sync().await;
        match self.unless_moved(self.direct()).await {
            None => self.aborted(Next::Usual),
            Some(true) => self.lost(if cut { "cut" } else { "dead" }),
            Some(false) if !self.offline => {
                self.offline = true;
                self.log(format_args!(
                    "offline: nothing past the tunnel either; tunnel kept"
                ));
            }
            Some(false) => {}
        }
    }

    /// Writes what a check found; true when the tunnel carries.
    fn report(&self, found: Option<&Found>, next: Next) -> bool {
        match (found, next) {
            (Some(Found::Ping(rtt)), _) => {
                self.log(format_args!("check ping {}ms", rtt.as_millis()));
                true
            }
            (Some(Found::Tls(took)), _) => {
                self.log(format_args!(
                    "check tls {}ms, ping failed",
                    took.as_millis()
                ));
                true
            }
            (None, Next::Cut) => {
                self.log(format_args!("check cut: sent without reply, ping failed"));
                false
            }
            (None, Next::Woke) => {
                self.log(format_args!("check fail: ping after wake"));
                false
            }
            (None, Next::Usual) => {
                self.log(format_args!("check fail: ping and tls"));
                false
            }
        }
    }

    /// Internet past the tunnel: a probe bound to the physical interface, to
    /// targets that are not routed into a tunnel when there are such.
    async fn direct(&self) -> bool {
        let Some(n) = &self.network else {
            return false;
        };
        let free: Vec<Ipv4Addr> = TARGETS
            .into_iter()
            .filter(|&t| !self.resolver.covers(t))
            .collect();
        let targets = if free.is_empty() {
            &TARGETS[..]
        } else {
            &free[..]
        };
        if probe::ping(n.bound(), targets, PING).await.is_some() {
            return true;
        }
        probe::tls(&n.iface, DIRECT_TLS).await
    }

    fn recovered(&mut self, now: Instant) {
        if let Some((what, at)) = self.pending.take() {
            self.log(format_args!(
                "recovered {what} in {}ms",
                now.duration_since(at).as_millis()
            ));
        }
    }
}
