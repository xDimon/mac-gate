//! Domain and subnet lists.
//!
//! A list is a text file, one entry per line: a domain suffix or an IPv4
//! address or CIDR. Empty lines and lines starting with `#` are skipped.
//! `*.example.com` means the suffix `example.com`: podkop drops such lines,
//! mac-gate keeps them.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subnet {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    pub fn host(addr: Ipv4Addr) -> Self {
        Self { addr, prefix: 32 }
    }

    pub fn netmask(self) -> Ipv4Addr {
        Ipv4Addr::from(mask(self.prefix))
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = mask(self.prefix);
        u32::from(ip) & mask == u32::from(self.addr)
    }

    pub fn overlaps(self, other: Subnet) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }

    fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok()?),
            None => (text, 32),
        };
        if prefix > 32 {
            return None;
        }
        let addr: Ipv4Addr = addr.parse().ok()?;
        Some(Self {
            addr: Ipv4Addr::from(u32::from(addr) & mask(prefix)),
            prefix,
        })
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

#[derive(Debug, Default)]
pub struct Lists {
    /// Suffix to the names of the lists that have it.
    suffixes: HashMap<String, Vec<String>>,
    subnets: Vec<(Subnet, String)>,
    /// Lines that are neither a domain nor an address, as "list: line".
    pub rejected: Vec<String>,
    /// The lists added, in order.
    names: Vec<String>,
}

impl Lists {
    /// Loads every `*.lst` file of `dir`, in name order; the list name is the
    /// file stem.
    pub fn load_dir(dir: &Path) -> io::Result<Self> {
        let mut paths: Vec<_> = fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "lst"))
            .collect();
        paths.sort();
        let mut lists = Self::default();
        for path in paths {
            let name = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            lists.add(&name, &fs::read_to_string(&path)?);
        }
        Ok(lists)
    }

    pub fn add(&mut self, name: &str, text: &str) {
        if !self.names.iter().any(|n| n == name) {
            self.names.push(name.to_owned());
        }
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(subnet) = Subnet::parse(line) {
                self.subnets.push((subnet, name.to_owned()));
                continue;
            }
            let bare = line
                .strip_prefix("*.")
                .or_else(|| line.strip_prefix('.'))
                .unwrap_or(line);
            let domain = normalize(bare);
            if is_domain(&domain) {
                let lists = self.suffixes.entry(domain).or_default();
                if !lists.iter().any(|l| l == name) {
                    lists.push(name.to_owned());
                }
            } else {
                self.rejected.push(format!("{name}: {line}"));
            }
        }
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn suffix_count(&self) -> usize {
        self.suffixes.len()
    }

    pub fn entry_count(&self) -> usize {
        self.suffixes.len() + self.subnets.len()
    }

    pub fn subnets(&self) -> impl Iterator<Item = (Subnet, &str)> {
        self.subnets.iter().map(|(s, n)| (*s, n.as_str()))
    }

    /// The lists whose suffixes cover `name`: the name itself or any of
    /// its parent domains. Empty when none does.
    pub fn match_domain(&self, name: &str) -> Vec<&str> {
        let name = normalize(name);
        let mut found: Vec<&str> = Vec::new();
        let mut rest = name.as_str();
        loop {
            for list in self.suffixes.get(rest).into_iter().flatten() {
                if !found.contains(&list.as_str()) {
                    found.push(list);
                }
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => return found,
            }
        }
    }
}

/// Lower case, without the trailing root dot.
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn is_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists() -> Lists {
        let mut l = Lists::default();
        l.add(
            "custom",
            "# comment\n\nexample.com\n*.wild.org\nBad Line\n  Spaced.NET.  \n",
        );
        l.add("telegram", "telegram.org\n149.154.160.0/20\n91.108.4.1\n");
        l.add("other", "example.com\n");
        l
    }

    #[test]
    fn suffix_matches_name_and_subdomains() {
        let l = lists();
        assert_eq!(l.match_domain("example.com"), ["custom", "other"]);
        assert_eq!(l.match_domain("a.b.example.com."), ["custom", "other"]);
        assert_eq!(l.match_domain("WWW.Example.COM"), ["custom", "other"]);
        assert!(l.match_domain("notexample.com").is_empty());
        assert!(l.match_domain("com").is_empty());
        assert!(l.match_domain("").is_empty());
    }

    #[test]
    fn wildcard_is_a_suffix() {
        let l = lists();
        assert_eq!(l.match_domain("wild.org"), ["custom"]);
        assert_eq!(l.match_domain("x.wild.org"), ["custom"]);
    }

    #[test]
    fn leading_dot_is_a_suffix() {
        let mut l = Lists::default();
        l.add("regional", ".test\n");
        assert_eq!(l.match_domain("host.test"), ["regional"]);
        assert_eq!(l.match_domain("a.b.test"), ["regional"]);
        assert!(l.match_domain("test.com").is_empty());
        assert!(l.rejected.is_empty());
    }

    #[test]
    fn every_list_of_a_name_in_the_order_added() {
        let mut l = lists();
        l.add("custom", "example.com\n");
        l.add("parent", "com\n");
        l.add("deep", "b.example.com\n");
        assert_eq!(
            l.match_domain("a.b.example.com"),
            ["deep", "custom", "other", "parent"]
        );
    }

    #[test]
    fn trims_and_rejects() {
        let l = lists();
        assert_eq!(l.match_domain("spaced.net"), ["custom"]);
        assert_eq!(l.rejected, vec!["custom: Bad Line".to_owned()]);
        assert_eq!(l.suffix_count(), 4);
    }

    #[test]
    fn subnets_and_hosts() {
        let l = lists();
        let covered = |ip: &str| {
            let ip = ip.parse().unwrap();
            l.subnets().find(|(s, _)| s.contains(ip)).map(|(_, n)| n)
        };
        assert_eq!(covered("149.154.167.99"), Some("telegram"));
        assert_eq!(covered("149.154.176.1"), None);
        assert_eq!(covered("91.108.4.1"), Some("telegram"));
        assert_eq!(covered("91.108.4.2"), None);
        assert_eq!(l.subnets().count(), 2);
    }

    #[test]
    fn subnet_parse_normalizes() {
        let s = Subnet::parse("10.1.2.3/8").unwrap();
        assert_eq!(s.to_string(), "10.0.0.0/8");
        assert!(Subnet::parse("10.0.0.0/33").is_none());
        assert!(Subnet::parse("example.com").is_none());
        assert_eq!(Subnet::parse("0.0.0.0/0").unwrap().prefix, 0);
    }

    #[test]
    fn overlap_either_way() {
        let wide = Subnet::parse("198.0.0.0/8").unwrap();
        let fake = Subnet::parse("198.18.0.0/15").unwrap();
        let other = Subnet::parse("198.20.0.0/16").unwrap();
        assert!(wide.overlaps(fake));
        assert!(fake.overlaps(wide));
        assert!(!fake.overlaps(other));
    }
}
