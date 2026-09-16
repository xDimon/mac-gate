//! The DNS of the Mac: every network service is set to the resolver, and
//! what each had is kept in a file next to the state until a stop puts it
//! back. A crash leaves both, and the next start keeps the file it finds.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crate::command;
use crate::pf::write_private;

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SAVED: &str = "dns-saved";
const LOCAL: &str = "127.0.0.1";
const STEP: Duration = Duration::from_secs(10);

/// A service and the servers it had; none means those from DHCP.
type Entry = (String, Vec<String>);

/// Services as `-listallnetworkservices` prints them: the first line
/// explains the asterisk that marks a disabled one.
fn parse_services(out: &str) -> Vec<String> {
    out.lines()
        .skip(1)
        .map(|l| l.strip_prefix('*').unwrap_or(l))
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Addresses in what `-getdnsservers` prints; "There aren't any" has none.
fn parse_servers(out: &str) -> Vec<String> {
    out.split_whitespace()
        .filter(|w| w.parse::<IpAddr>().is_ok())
        .map(str::to_owned)
        .collect()
}

fn parse_saved(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| {
            let (svc, servers) = l.split_once('\t')?;
            Some((
                svc.to_owned(),
                servers.split_whitespace().map(str::to_owned).collect(),
            ))
        })
        .collect()
}

fn format_saved(entries: &[Entry]) -> String {
    entries.iter().fold(String::new(), |mut s, (svc, servers)| {
        let _ = writeln!(s, "{svc}\t{}", servers.join(" "));
        s
    })
}

fn load(path: &Path) -> io::Result<Option<Vec<Entry>>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(parse_saved(&text))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

async fn services() -> io::Result<Vec<String>> {
    command::run(NETWORKSETUP, &["-listallnetworkservices"], None, STEP)
        .await
        .map(|out| parse_services(&out))
}

async fn servers(svc: &str) -> io::Result<Vec<String>> {
    command::run(NETWORKSETUP, &["-getdnsservers", svc], None, STEP)
        .await
        .map(|out| parse_servers(&out))
}

async fn set(svc: &str, servers: &[String]) -> io::Result<()> {
    let mut args = vec!["-setdnsservers".to_owned(), svc.to_owned()];
    if servers.is_empty() {
        args.push("Empty".to_owned());
    } else {
        args.extend(servers.iter().cloned());
    }
    command::run(NETWORKSETUP, &args, None, STEP)
        .await
        .map(drop)
}

async fn flush() {
    let _ = command::run("/usr/bin/dscacheutil", &["-flushcache"], None, STEP).await;
    let _ = command::run("/usr/bin/killall", &["-HUP", "mDNSResponder"], None, STEP).await;
}

pub fn saved(dir: &Path) -> bool {
    dir.join(SAVED).exists()
}

/// Sets every service to the resolver. A service the file lacks has what
/// it had written there first, without the resolver's own address: put
/// back, that would leave the Mac without names. A service that fails is
/// skipped, not the rest: the first error is returned after them. Returns
/// the services set.
pub async fn take_over(dir: &Path) -> io::Result<usize> {
    let path = dir.join(SAVED);
    let mut saved = load(&path)?.unwrap_or_default();
    let mut changed = false;
    let mut todo = Vec::new();
    let mut first = None;
    for svc in services().await? {
        let now = match servers(&svc).await {
            Ok(now) => now,
            Err(e) => {
                first.get_or_insert(e);
                continue;
            }
        };
        if !saved.iter().any(|(s, _)| *s == svc) {
            let kept = now.iter().filter(|s| *s != LOCAL).cloned().collect();
            saved.push((svc.clone(), kept));
            changed = true;
        }
        if now != [LOCAL] {
            todo.push(svc);
        }
    }
    if changed {
        // Whole or not at all: a torn file would put back half the DNS.
        let tmp = dir.join(format!("{SAVED}.new"));
        write_private(&tmp, &format_saved(&saved))?;
        fs::rename(&tmp, &path)?;
    }
    let mut n = 0;
    for svc in &todo {
        match set(svc, &[LOCAL.to_owned()]).await {
            Ok(()) => n += 1,
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    if n > 0 {
        flush().await;
    }
    first.map_or(Ok(n), Err)
}

/// Puts back what the file kept, for the services still there, and removes
/// the file once every one went back. Without the file, nothing to do.
pub async fn give_back(dir: &Path) -> io::Result<usize> {
    let path = dir.join(SAVED);
    let Some(saved) = load(&path)? else {
        return Ok(0);
    };
    let present = services().await?;
    let mut first = None;
    let mut n = 0;
    for (svc, servers) in saved.iter().filter(|(s, _)| present.contains(s)) {
        match set(svc, servers).await {
            Ok(()) => n += 1,
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    flush().await;
    match first {
        Some(e) => Err(e),
        None => fs::remove_file(&path).map(|()| n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_without_the_header_and_asterisk() {
        let out = "An asterisk (*) denotes that a network service is disabled.\n\
                   Wi-Fi\n*Thunderbolt Bridge\nEthernet (PPPoE)\n";
        assert_eq!(
            parse_services(out),
            vec!["Wi-Fi", "Thunderbolt Bridge", "Ethernet (PPPoE)"]
        );
    }

    #[test]
    fn servers_or_none() {
        assert_eq!(
            parse_servers("1.1.1.1\n8.8.8.8\n"),
            vec!["1.1.1.1", "8.8.8.8"]
        );
        assert!(parse_servers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert!(
            parse_servers(
                "(Please note: Thunderbolt Bridge is currently disabled) \
                 There aren't any DNS Servers set on Thunderbolt Bridge.\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn saved_round_trip() {
        let entries = vec![
            ("Wi-Fi".to_owned(), vec!["192.168.1.1".to_owned()]),
            ("USB 10/100/1000 LAN".to_owned(), Vec::new()),
            (
                "Ethernet (PPPoE)".to_owned(),
                vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()],
            ),
        ];
        assert_eq!(parse_saved(&format_saved(&entries)), entries);
    }
}
