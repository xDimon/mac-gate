//! Host routes on disk: address, the time of its last answer and its rule,
//! one per line. Kept so that routes outlive a restart of the daemon and a
//! new tunnel interface.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    /// The rule whose tunnel takes the address; files of earlier versions
    /// name a list here.
    pub rule: String,
    /// Unix seconds of the last answer that carried the address.
    pub last: u64,
}

pub type Hosts = HashMap<Ipv4Addr, Host>;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Lines that do not parse are skipped: a damaged line costs one route.
pub fn parse(text: &str) -> Hosts {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let ip = f.next()?.parse().ok()?;
            let seen = f.next()?.parse().ok()?;
            let rule = f.next()?.to_owned();
            Some((ip, Host { rule, last: seen }))
        })
        .collect()
}

pub fn format(hosts: &Hosts) -> String {
    let mut ips: Vec<&Ipv4Addr> = hosts.keys().collect();
    ips.sort();
    ips.into_iter()
        .filter_map(|ip| {
            let h = hosts.get(ip)?;
            Some(format!("{ip} {} {}\n", h.last, h.rule))
        })
        .collect()
}

/// A missing file is an empty state.
pub fn load(path: &Path) -> io::Result<Hosts> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse(&text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Hosts::new()),
        Err(e) => Err(e),
    }
}

/// Written aside and renamed over: a crash leaves the old file or the new.
pub fn save(path: &Path, hosts: &Hosts) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(format(hosts).as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, last: u64) -> Host {
        Host {
            rule: name.to_owned(),
            last,
        }
    }

    #[test]
    fn round_trip_sorted() {
        let mut h = Hosts::new();
        h.insert(Ipv4Addr::new(9, 9, 9, 9), host("custom", 200));
        h.insert(Ipv4Addr::new(1, 2, 3, 4), host("telegram", 100));
        let text = format(&h);
        assert_eq!(text, "1.2.3.4 100 telegram\n9.9.9.9 200 custom\n");
        assert_eq!(parse(&text), h);
    }

    #[test]
    fn skips_damaged_lines() {
        let h = parse("1.2.3.4 100 x\nbad\n5.6.7.8 notanumber y\n5.6.7.9 7\n\n");
        assert_eq!(h.len(), 1);
        assert_eq!(h.get(&Ipv4Addr::new(1, 2, 3, 4)), Some(&host("x", 100)));
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join(format!("mac-gate-state-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("routes");
        assert!(load(&path).unwrap().is_empty());
        let mut h = Hosts::new();
        h.insert(Ipv4Addr::new(1, 2, 3, 4), host("x", 5));
        save(&path, &h).unwrap();
        assert_eq!(load(&path).unwrap(), h);
        fs::remove_dir_all(&dir).unwrap();
    }
}
