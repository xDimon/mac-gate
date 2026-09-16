//! Liveness probes: ICMP echo from a socket bound to an interface, TLS by
//! curl through an interface, and the byte counters of an interface.

use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::command;

/// Addresses answered from anycast close to any exit; no DNS needed.
pub const TARGETS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
];

/// Pings every target at once from a socket bound to `bound` and returns
/// the time to the first reply, or None if none came within `limit`.
pub async fn ping(
    bound: Option<NonZeroU32>,
    targets: &[Ipv4Addr],
    limit: Duration,
) -> Option<Duration> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).ok()?;
    if let Some(index) = bound {
        s.bind_device_by_index_v4(Some(index)).ok()?;
    }
    s.set_nonblocking(true).ok()?;
    let sock = UdpSocket::from_std(std::net::UdpSocket::from(s)).ok()?;
    let (id, seq) = ids();
    let packet = echo(id, seq);
    let start = Instant::now();
    for &t in targets {
        let _ = sock.send_to(&packet, SocketAddr::from((t, 0))).await;
    }
    let wait = async {
        let mut buf = [0u8; 1500];
        loop {
            let (n, _) = sock.recv_from(&mut buf).await.ok()?;
            if is_reply(buf.get(..n).unwrap_or_default(), id, seq) {
                return Some(start.elapsed());
            }
        }
    };
    timeout(limit, wait).await.ok().flatten()
}

/// An HTTPS request through `iface`; true when it completed within `limit`.
pub async fn tls(iface: &str, limit: Duration) -> bool {
    let secs = format!("{:.1}", limit.as_secs_f64());
    command::run(
        "/usr/bin/curl",
        &[
            "-s",
            "-o",
            "/dev/null",
            "-m",
            &secs,
            "--interface",
            iface,
            "https://1.1.1.1/cdn-cgi/trace",
        ],
        None,
        limit + Duration::from_secs(2),
    )
    .await
    .is_ok()
}

/// Packets and bytes an interface received and sent, as netstat counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

pub async fn counters(iface: &str) -> Option<Counters> {
    let out = command::run(
        "/usr/sbin/netstat",
        &["-I", iface, "-b", "-n"],
        None,
        Duration::from_secs(5),
    )
    .await
    .ok()?;
    parse_counters(&out, iface)
}

/// The link row: the interface and `<Link#N>`, then the counters; utun has
/// no link address, so fields are counted from the end.
fn parse_counters(out: &str, iface: &str) -> Option<Counters> {
    out.lines().find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() != Some(&iface) || !f.get(2)?.starts_with("<Link#") {
            return None;
        }
        let back = |k: usize| -> Option<u64> { f.get(f.len().checked_sub(k)?)?.parse().ok() };
        Some(Counters {
            rx_packets: back(7)?,
            rx_bytes: back(5)?,
            tx_packets: back(4)?,
            tx_bytes: back(2)?,
        })
    })
}

fn ids() -> (u16, u16) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let pid = std::process::id();
    (
        u16::try_from(pid & 0xffff).unwrap_or(0),
        u16::try_from(nanos & 0xffff).unwrap_or(0),
    )
}

fn echo(id: u16, seq: u16) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[0] = 8;
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    p[8..].copy_from_slice(b"mac-gate");
    let sum = checksum(&p);
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

/// An echo reply with our id and sequence; macOS hands datagram ICMP
/// sockets the IP header too, so it is skipped when present.
fn is_reply(buf: &[u8], id: u16, seq: u16) -> bool {
    let icmp = match buf.first() {
        Some(b) if b >> 4 == 4 => buf.get(usize::from(b & 0x0f) * 4..),
        _ => Some(buf),
    };
    let Some(icmp) = icmp else { return false };
    icmp.len() >= 8
        && icmp[0] == 0
        && icmp[4..6] == id.to_be_bytes()
        && icmp[6..8] == seq.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_checksum_verifies() {
        let p = echo(0x1234, 0xabcd);
        assert_eq!(p[0], 8);
        assert_eq!(checksum(&p), 0);
    }

    #[test]
    fn reply_with_and_without_ip_header() {
        let mut r = echo(7, 9);
        r[0] = 0;
        assert!(is_reply(&r, 7, 9));
        assert!(!is_reply(&r, 7, 10));
        let mut with_ip = vec![0x45u8];
        with_ip.extend_from_slice(&[0; 19]);
        with_ip.extend_from_slice(&r);
        assert!(is_reply(&with_ip, 7, 9));
        assert!(!is_reply(&echo(7, 9), 7, 9));
        assert!(!is_reply(&[0x45, 0], 7, 9));
    }

    #[test]
    fn counters_of_the_link_row() {
        let out = "\
Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
utun4      1280  <Link#23>                           12     0       1234       10     0        987     0
utun4      1280  10.7.0.2/32   10.7.0.2              12     -       1234       10     -        987     -
en0        1500  <Link#14>   00:00:5e:00:53:01  1000000     0 12345678901   500000     0  9876543210     0
";
        assert_eq!(
            parse_counters(out, "utun4"),
            Some(Counters {
                rx_packets: 12,
                rx_bytes: 1234,
                tx_packets: 10,
                tx_bytes: 987,
            })
        );
        assert_eq!(
            parse_counters(out, "en0"),
            Some(Counters {
                rx_packets: 1_000_000,
                rx_bytes: 12_345_678_901,
                tx_packets: 500_000,
                tx_bytes: 9_876_543_210,
            })
        );
        assert_eq!(parse_counters(out, "utun9"), None);
    }
}
