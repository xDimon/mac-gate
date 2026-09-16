//! The kill switch in pf: addresses of the lists leave only through the
//! tunnels of their rule. The rules live in an anchor under `com.apple`,
//! which the main ruleset evaluates, and stay in the kernel when the daemon
//! dies; only a stop takes them away. Each rule in force has two tables:
//! its routed hosts and its list subnets. When the network resolver answers
//! with fake addresses the subnets may go to the router, which sends them
//! into its own tunnel.

use std::fmt::{self, Write as _};
use std::fs;
use std::io::{self, Write as _};
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::Mutex;

use crate::command;
use crate::lists::Subnet;
use crate::probe::TARGETS;

pub const ANCHOR: &str = "com.apple/mac-gate";
const PFCTL: &str = "/sbin/pfctl";
const HOSTS: &str = "mac_gate_h";
const NETS: &str = "mac_gate_n";
const HOSTS_FILE: &str = "pf-hosts";
const NETS_FILE: &str = "pf-nets";
const TOKEN_FILE: &str = "pf-token";
const STEP: Duration = Duration::from_secs(10);

/// What the rules depend on besides the tables; a change reloads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shape {
    /// Per rule, in the order of the settings: none for a rule not in
    /// force, which holds nothing; else the tunnel interfaces its addresses
    /// may leave through, none while it has no tunnel.
    pub rules: Vec<Option<Vec<String>>>,
    /// The subnets are left to the router.
    pub use_fakeip: bool,
    /// The tunnel servers, open whatever list covers them.
    pub endpoints: Vec<Ipv4Addr>,
    /// The physical interface and the network DNS.
    pub network: Option<(String, Ipv4Addr)>,
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rules: Vec<String> = self
            .rules
            .iter()
            .map(|r| match r {
                None => "off".to_owned(),
                Some(t) if t.is_empty() => "none".to_owned(),
                Some(t) => t.join(","),
            })
            .collect();
        let endpoints: Vec<String> = self.endpoints.iter().map(ToString::to_string).collect();
        write!(
            f,
            "rules={} use_fakeip={} endpoints={} network={}",
            rules.join(" "),
            self.use_fakeip,
            if endpoints.is_empty() {
                "none".to_owned()
            } else {
                endpoints.join(",")
            },
            self.network
                .as_ref()
                .map_or_else(|| "none".to_owned(), |(i, d)| format!("{i} dns={d}")),
        )
    }
}

fn table_file(dir: &Path, kind: &str, rule: usize) -> PathBuf {
    dir.join(format!("{kind}-{rule}"))
}

/// The anchor ruleset. Blocks drop rather than reject: a connection held
/// up while the tunnel comes back goes through on a retransmit. The passes
/// only exempt from the blocks and keep no state: a state would carry the
/// replies past every rule, any other anchor's included. All passes come
/// before any block: a subnet of one rule may hold a narrower one of
/// another, routed into that other's tunnel.
pub fn ruleset(shape: &Shape, dir: &Path) -> String {
    let mut r = String::new();
    let rules = || {
        shape
            .rules
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.as_ref().map(|t| (i, t)))
    };
    for (i, _) in rules() {
        for (table, kind) in [(HOSTS, HOSTS_FILE), (NETS, NETS_FILE)] {
            let _ = writeln!(
                r,
                "table <{table}{i}> persist file \"{}\"",
                table_file(dir, kind, i).display()
            );
        }
    }
    for ip in &shape.endpoints {
        let _ = writeln!(r, "pass out quick inet to {ip} no state");
    }
    if let Some((iface, dns)) = &shape.network {
        // Names outside the lists, the upstream FakeIP probe and the country.
        let _ = writeln!(
            r,
            "pass out quick on {iface} inet proto {{ udp tcp }} to {dns} port 53 no state"
        );
        // The probe for internet past the tunnel.
        let targets: Vec<String> = TARGETS.iter().map(ToString::to_string).collect();
        let _ = writeln!(
            r,
            "pass out quick on {iface} inet proto icmp to {{ {} }} icmp-type echoreq no state",
            targets.join(" ")
        );
    }
    for (i, tunnels) in rules() {
        let on = match tunnels.as_slice() {
            [] => continue,
            [one] => one.clone(),
            many => format!("{{ {} }}", many.join(" ")),
        };
        for table in [HOSTS, NETS] {
            let _ = writeln!(r, "pass out quick on {on} inet to <{table}{i}> no state");
        }
    }
    for (i, _) in rules() {
        let _ = writeln!(r, "block drop out quick inet to <{HOSTS}{i}>");
        if !shape.use_fakeip {
            let _ = writeln!(r, "block drop out quick inet to <{NETS}{i}>");
        }
    }
    r
}

/// The token in what `pfctl -E` prints: "Token : 1234".
fn parse_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        (key.trim() == "Token" && !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.to_owned())
    })
}

pub fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(text.as_bytes())
}

/// Addresses in what `pfctl -T show` prints, one indented per line.
fn parse_table(text: &str) -> Vec<Ipv4Addr> {
    text.split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect()
}

fn lines<T: fmt::Display>(items: impl IntoIterator<Item = T>) -> String {
    items.into_iter().fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "{i}");
        s
    })
}

/// The tables of the rules: hosts and subnets, by rule.
pub struct Tables {
    pub hosts: Vec<Vec<Ipv4Addr>>,
    pub nets: Vec<Vec<Subnet>>,
}

pub struct Pf {
    dir: PathBuf,
    /// Held across a table snapshot and its load, and by every table
    /// change, so that no change falls between the two.
    lock: Mutex<()>,
}

impl Pf {
    /// Keeps its files and the enable token in `dir`.
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
            lock: Mutex::new(()),
        }
    }

    /// Takes a reference on pf being enabled, and releases the one a dead
    /// daemon left behind.
    pub async fn enable(&self) -> io::Result<()> {
        let path = self.dir.join(TOKEN_FILE);
        let old = fs::read_to_string(&path).ok();
        let (out, err) = command::run_both(PFCTL, &["-E"], None, STEP).await?;
        let token = parse_token(&out)
            .or_else(|| parse_token(&err))
            .ok_or_else(|| io::Error::other("pfctl -E gave no token"))?;
        write_private(&path, &format!("{token}\n"))?;
        if let Some(old) = old
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty() && *t != token)
        {
            let _ = command::run(PFCTL, &["-X", old], None, STEP).await;
        }
        Ok(())
    }

    /// Replaces the rules and every table at once; the tables are taken
    /// under the lock.
    pub async fn load(&self, shape: &Shape, tables: impl FnOnce() -> Tables) -> io::Result<()> {
        let _held = self.lock.lock().await;
        let t = tables();
        for i in 0..shape.rules.len() {
            let hosts = t.hosts.get(i).map(lines).unwrap_or_default();
            let nets = t.nets.get(i).map(lines).unwrap_or_default();
            write_private(&table_file(&self.dir, HOSTS_FILE, i), &hosts)?;
            write_private(&table_file(&self.dir, NETS_FILE, i), &nets)?;
        }
        let rules = ruleset(shape, &self.dir);
        command::run(
            PFCTL,
            &["-q", "-a", ANCHOR, "-f", "-"],
            Some(rules.as_bytes()),
            STEP,
        )
        .await
        .map(drop)
    }

    /// The host tables of the first `rules` rules as the kernel holds
    /// them: after a crash, the addresses answered since the last save too.
    /// Empty without the tables, as after a stop or a reboot.
    pub async fn held_hosts(&self, rules: usize) -> Vec<(usize, Ipv4Addr)> {
        let mut held = Vec::new();
        for i in 0..rules {
            let table = format!("{HOSTS}{i}");
            if let Ok(out) = command::run(
                PFCTL,
                &["-q", "-a", ANCHOR, "-t", &table, "-T", "show"],
                None,
                STEP,
            )
            .await
            {
                held.extend(parse_table(&out).into_iter().map(|ip| (i, ip)));
            }
        }
        held
    }

    pub async fn add(&self, rule: usize, ips: &[Ipv4Addr]) -> io::Result<()> {
        self.table("add", rule, ips).await
    }

    pub async fn delete(&self, rule: usize, ips: &[Ipv4Addr]) -> io::Result<()> {
        self.table("delete", rule, ips).await
    }

    async fn table(&self, op: &str, rule: usize, ips: &[Ipv4Addr]) -> io::Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let _held = self.lock.lock().await;
        let table = format!("{HOSTS}{rule}");
        let mut args: Vec<String> = ["-q", "-a", ANCHOR, "-t", &table, "-T", op]
            .map(str::to_owned)
            .into();
        args.extend(ips.iter().map(ToString::to_string));
        command::run(PFCTL, &args, None, STEP).await.map(drop)
    }

    /// Takes the rules and tables away and releases pf; every part is
    /// tried, the first error is returned.
    pub async fn release(&self) -> io::Result<()> {
        let _held = self.lock.lock().await;
        let rules = command::run(PFCTL, &["-q", "-a", ANCHOR, "-F", "rules"], None, STEP).await;
        let tables = command::run(PFCTL, &["-q", "-a", ANCHOR, "-F", "Tables"], None, STEP).await;
        let path = self.dir.join(TOKEN_FILE);
        let token = match fs::read_to_string(&path) {
            Ok(t) => command::run(PFCTL, &["-X", t.trim()], None, STEP).await,
            Err(e) => Err(e),
        };
        let _ = fs::remove_file(&path);
        // The table files of every rule, and those of versions before rules.
        if let Ok(names) = fs::read_dir(&self.dir) {
            for path in names.filter_map(Result::ok).map(|e| e.path()) {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name.starts_with(HOSTS_FILE) || name.starts_with(NETS_FILE) {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        rules.and(tables).and(token).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> Shape {
        Shape {
            rules: vec![
                Some(vec!["utun4".to_owned(), "utun5".to_owned()]),
                None,
                Some(vec!["utun6".to_owned()]),
            ],
            use_fakeip: false,
            endpoints: vec![
                Ipv4Addr::new(203, 0, 113, 7),
                Ipv4Addr::new(198, 51, 100, 9),
            ],
            network: Some(("en0".to_owned(), Ipv4Addr::new(192, 168, 1, 1))),
        }
    }

    fn starting(rules: &str, word: &str) -> Vec<String> {
        rules
            .lines()
            .filter(|l| l.starts_with(word))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn through_the_tunnels_of_the_rule_only() {
        let r = ruleset(&shape(), Path::new("/d"));
        assert_eq!(
            starting(&r, "table"),
            [
                "table <mac_gate_h0> persist file \"/d/pf-hosts-0\"",
                "table <mac_gate_n0> persist file \"/d/pf-nets-0\"",
                "table <mac_gate_h2> persist file \"/d/pf-hosts-2\"",
                "table <mac_gate_n2> persist file \"/d/pf-nets-2\"",
            ]
        );
        assert_eq!(
            starting(&r, "block"),
            [
                "block drop out quick inet to <mac_gate_h0>",
                "block drop out quick inet to <mac_gate_n0>",
                "block drop out quick inet to <mac_gate_h2>",
                "block drop out quick inet to <mac_gate_n2>",
            ]
        );
        assert!(r.contains("pass out quick on { utun4 utun5 } inet to <mac_gate_h0> no state\n"));
        assert!(r.contains("pass out quick on utun6 inet to <mac_gate_n2> no state\n"));
        assert!(r.contains("pass out quick inet to 203.0.113.7 no state\n"));
        assert!(r.contains("pass out quick inet to 198.51.100.9 no state\n"));
        assert!(r.contains(
            "pass out quick on en0 inet proto { udp tcp } to 192.168.1.1 port 53 no state\n"
        ));
        let first_block = r.find("block").unwrap();
        assert!(r.rfind("pass").unwrap() < first_block);
        assert_eq!(
            shape().to_string(),
            "rules=utun4,utun5 off utun6 use_fakeip=false endpoints=203.0.113.7,198.51.100.9 network=en0 dns=192.168.1.1"
        );
    }

    #[test]
    fn no_tunnel_blocks_everywhere_and_fakeip_frees_subnets() {
        let s = Shape {
            rules: vec![Some(Vec::new())],
            use_fakeip: true,
            endpoints: Vec::new(),
            network: None,
        };
        let r = ruleset(&s, Path::new("/d"));
        assert_eq!(
            starting(&r, "block"),
            ["block drop out quick inet to <mac_gate_h0>"]
        );
        assert!(!r.contains("pass"));
        assert_eq!(
            s.to_string(),
            "rules=none use_fakeip=true endpoints=none network=none"
        );
    }

    #[test]
    fn table_addresses() {
        assert_eq!(
            parse_table("   203.0.113.10\n   198.51.100.20\n"),
            vec![
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(198, 51, 100, 20)
            ]
        );
        assert!(parse_table("").is_empty());
    }

    #[test]
    fn token() {
        assert_eq!(
            parse_token("pf enabled\nToken : 13852412398563\n"),
            Some("13852412398563".to_owned())
        );
        assert_eq!(parse_token("pf enabled\n"), None);
        assert_eq!(parse_token("Token : x1\n"), None);
    }

    /// pfctl parses a ruleset without root when told not to load it.
    #[test]
    fn ruleset_parses() {
        let dir = std::env::temp_dir().join(format!("mac-gate-pf-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for i in 0..3 {
            fs::write(
                table_file(&dir, HOSTS_FILE, i),
                lines([Ipv4Addr::new(1, 2, 3, 4)]),
            )
            .unwrap();
            fs::write(table_file(&dir, NETS_FILE, i), "149.154.160.0/20\n").unwrap();
        }
        for s in [shape(), Shape::default()] {
            let out = std::process::Command::new(PFCTL)
                .args(["-n", "-f", "-"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .and_then(|mut c| {
                    c.stdin
                        .take()
                        .unwrap()
                        .write_all(ruleset(&s, &dir).as_bytes())?;
                    c.wait()
                })
                .unwrap();
            assert!(out.success(), "{s}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
