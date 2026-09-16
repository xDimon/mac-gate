//! The network the Mac is on: the primary interface, its gateway and the DNS
//! its DHCP gave; whether that DNS answers with fake addresses; sleep;
//! interface events.

use std::fmt;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU32;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use socket2::{Domain, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::command;
use crate::resolver::{has_fakeip, ipv4_answers};
use crate::route;
use crate::upstream::Upstream;

const SHORT: Duration = Duration::from_secs(5);
/// podkop answers this name with a fake address.
const FAKEIP_PROBE: &str = "fakeip.podkop.fyi.";
/// Wall time ahead of monotonic time by more than this is sleep.
const SLEEP_GAP: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub iface: String,
    pub index: u16,
    pub addr: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: Ipv4Addr,
}

impl Network {
    pub fn bound(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(u32::from(self.index))
    }

    /// The network DNS, asked from a socket bound to the interface: list
    /// routes into the tunnel must not catch it.
    pub fn upstream(&self) -> Upstream {
        Upstream {
            server: SocketAddrV4::new(self.dns, 53),
            bound_if: self.bound(),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} gw={} dns={}",
            self.iface, self.addr, self.gateway, self.dns
        )
    }
}

/// The network of the default route, or None when there is none. The DNS
/// is the one DHCP gave, whatever the Mac itself is set to use; without it,
/// the gateway.
pub async fn current() -> Option<Network> {
    let out = command::run("/sbin/route", &["-n", "get", "default"], None, SHORT)
        .await
        .ok()?;
    let (gateway, iface) = parse_route_get(&out)?;
    let index = route::if_index(&iface).ok()?;
    let ipconfig = "/usr/sbin/ipconfig";
    let addr = command::run(ipconfig, &["getifaddr", iface.as_str()], None, SHORT)
        .await
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let dns = command::run(
        ipconfig,
        &["getoption", iface.as_str(), "domain_name_server"],
        None,
        SHORT,
    )
    .await
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(gateway);
    Some(Network {
        iface,
        index,
        addr,
        gateway,
        dns,
    })
}

fn parse_route_get(out: &str) -> Option<(Ipv4Addr, String)> {
    let mut gateway = None;
    let mut iface = None;
    for line in out.lines() {
        match line.trim().split_once(':') {
            Some(("gateway", v)) => gateway = v.trim().parse().ok(),
            Some(("interface", v)) => iface = Some(v.trim().to_owned()),
            _ => {}
        }
    }
    Some((gateway?, iface?))
}

pub async fn query_a(up: Upstream, name: &str, limit: Duration) -> io::Result<Message> {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let mut msg = Message::new(
        u16::try_from(id & 0xffff).unwrap_or(0),
        MessageType::Query,
        OpCode::Query,
    );
    msg.metadata.recursion_desired = true;
    let name = Name::from_ascii(name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    msg.add_query(Query::query(name, RecordType::A));
    let bytes = msg.to_vec().map_err(|e| io::Error::other(e.to_string()))?;
    let answer = up.exchange(&bytes, limit).await?;
    Message::from_vec(&answer).map_err(|e| io::Error::other(e.to_string()))
}

pub async fn upstream_has_fakeip(up: Upstream) -> io::Result<bool> {
    Ok(has_fakeip(&query_a(up, FAKEIP_PROBE, SHORT).await?))
}

pub async fn resolve_ipv4(up: Upstream, name: &str) -> io::Result<Ipv4Addr> {
    ipv4_answers(&query_a(up, name, SHORT).await?)
        .first()
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {name}")))
}

/// Notices sleep: wall time runs through it, `Instant` on macOS does not.
pub struct Clock {
    wall: SystemTime,
    mono: Instant,
}

impl Default for Clock {
    fn default() -> Self {
        Self {
            wall: SystemTime::now(),
            mono: Instant::now(),
        }
    }
}

impl Clock {
    /// How long the Mac slept since the last call, if it did.
    pub fn slept(&mut self) -> Option<Duration> {
        let (wall, mono) = (SystemTime::now(), Instant::now());
        let dw = wall.duration_since(self.wall).unwrap_or_default();
        let dm = mono.duration_since(self.mono);
        self.wall = wall;
        self.mono = mono;
        dw.checked_sub(dm).filter(|gap| *gap > SLEEP_GAP)
    }
}

/// Interface and address changes, from a routing socket of its own.
pub struct RouteEvents(AsyncFd<Socket>);

impl RouteEvents {
    pub fn open() -> io::Result<Self> {
        let s = Socket::new(Domain::from(libc::PF_ROUTE), Type::RAW, None)?;
        s.set_nonblocking(true)?;
        Ok(Self(AsyncFd::new(s)?))
    }

    /// Waits for a message about an interface or its addresses; route
    /// messages, this process's own among them, are skipped.
    pub async fn next(&self) -> io::Result<()> {
        let mut buf = [0u8; 2048];
        loop {
            let mut guard = self.0.readable().await?;
            let got = guard.try_io(|fd| {
                let mut s: &Socket = fd.get_ref();
                s.read(&mut buf)
            });
            match got {
                Ok(Ok(n)) if n > 3 && buf.get(3).is_some_and(|&t| is_link_event(t)) => {
                    return Ok(());
                }
                // Overflow: messages were lost, and one of them may have mattered.
                Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Ok(Ok(_)) | Err(_) => {}
            }
        }
    }
}

fn is_link_event(kind: u8) -> bool {
    matches!(
        i32::from(kind),
        libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_get_default() {
        let out = "   route to: default\ndestination: default\n       mask: default\n    \
                   gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(
            parse_route_get(out),
            Some((Ipv4Addr::new(192, 168, 1, 1), "en0".to_owned()))
        );
        assert_eq!(parse_route_get("  interface: utun4\n"), None);
    }

    #[test]
    fn link_events() {
        assert!(is_link_event(0xc));
        assert!(is_link_event(0xe));
        assert!(!is_link_event(1));
    }
}
