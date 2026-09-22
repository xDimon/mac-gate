//! One tunnel: amneziawg-go as a child process on a fresh `utunN`,
//! configured from an awg-quick file without awg-quick.
//!
//! The interface gets its address, MTU and a default route scoped to itself,
//! and no other routes: what goes into the tunnel is decided by the resolver.
//! A reconnect is a new process, so a new source port.

use std::fmt::{self, Write as _};
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

use crate::command;
use crate::route;

const STEP: Duration = Duration::from_secs(10);
const IFCONFIG: &str = "/sbin/ifconfig";
const ROUTE: &str = "/sbin/route";

/// awg-quick keys of `[Interface]` that `awg setconf` does not take.
const QUICK_KEYS: [&str; 9] = [
    "address",
    "mtu",
    "table",
    "dns",
    "saveconfig",
    "preup",
    "postup",
    "predown",
    "postdown",
];

enum Line {
    Text(String),
    Endpoint,
}

/// An awg-quick file, split into what this module applies itself and the
/// rest, which goes to `awg setconf` as it is. No Debug: it holds the key.
pub struct Conf {
    pub address: Ipv4Addr,
    pub mtu: u16,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    /// Keys dropped without effect, such as DNS or hooks.
    pub ignored: Vec<String>,
    lines: Vec<Line>,
}

impl Conf {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut section = String::new();
        let mut address = None;
        let mut mtu = 1280;
        let mut endpoint = None;
        let mut ignored = Vec::new();
        let mut lines = Vec::new();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                section = line.to_ascii_lowercase();
                lines.push(Line::Text(line.to_owned()));
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("not a key = value line: {line}"));
            };
            let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
            if section == "[interface]" && QUICK_KEYS.contains(&key.as_str()) {
                match key.as_str() {
                    "address" => {
                        address = value
                            .split(',')
                            .find_map(|a| a.trim().split('/').next()?.parse().ok());
                    }
                    "mtu" => mtu = value.parse().map_err(|_| format!("bad MTU {value}"))?,
                    _ => ignored.push(key),
                }
                continue;
            }
            if section == "[peer]" && key == "endpoint" {
                if endpoint.is_some() {
                    return Err("more than one peer endpoint".to_owned());
                }
                let (host, port) = value
                    .rsplit_once(':')
                    .ok_or_else(|| format!("bad endpoint {value}"))?;
                let port = port
                    .parse()
                    .map_err(|_| format!("bad endpoint port {value}"))?;
                endpoint = Some((host.trim_matches(['[', ']']).to_owned(), port));
                lines.push(Line::Endpoint);
                continue;
            }
            lines.push(Line::Text(line.to_owned()));
        }
        let (endpoint_host, endpoint_port) = endpoint.ok_or("no peer endpoint")?;
        Ok(Self {
            address: address.ok_or("no IPv4 Address in [Interface]")?,
            mtu,
            endpoint_host,
            endpoint_port,
            ignored,
            lines,
        })
    }

    /// The endpoint address when the file gives one rather than a name.
    pub fn endpoint_ip(&self) -> Option<Ipv4Addr> {
        self.endpoint_host.parse().ok()
    }

    /// The text for `awg setconf`, with the endpoint as `ip`.
    fn setconf(&self, ip: Ipv4Addr) -> String {
        let mut out = String::new();
        for line in &self.lines {
            match line {
                Line::Text(t) => out.push_str(t),
                Line::Endpoint => {
                    let _ = write!(out, "Endpoint = {ip}:{}", self.endpoint_port);
                }
            }
            out.push('\n');
        }
        out
    }
}

#[derive(Clone)]
pub struct Tools {
    pub go: PathBuf,
    pub awg: PathBuf,
    /// Where amneziawg-go keeps its sockets and writes the interface name.
    pub run_dir: PathBuf,
}

pub struct Tunnel {
    pub name: String,
    pub index: u16,
    /// When the interface came up. Every tunnel watched here is a child of
    /// this process - those of a dead daemon are stopped, not adopted - so
    /// this is the age of the interface itself.
    pub up_at: Instant,
    child: Child,
    name_file: PathBuf,
}

impl fmt::Display for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.index)
    }
}

impl Tunnel {
    /// Starts amneziawg-go on a new interface and configures it; `seq` keeps
    /// the name files of concurrent tunnels apart.
    pub async fn up(tools: &Tools, conf: &Conf, endpoint: Ipv4Addr, seq: u32) -> io::Result<Self> {
        std::fs::create_dir_all(&tools.run_dir)?;
        let name_file = tools.run_dir.join(format!("mac-gate-{seq}.name"));
        let _ = std::fs::remove_file(&name_file);
        let mut child = Command::new(&tools.go)
            .args(["-f", "utun"])
            .env("WG_TUN_NAME_FILE", &name_file)
            .env("LOG_LEVEL", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let name = match wait_ready(&mut child, &name_file, &tools.run_dir).await {
            Ok(name) => name,
            Err(e) => {
                let _ = child.kill().await;
                let _ = std::fs::remove_file(&name_file);
                return Err(e);
            }
        };
        let mut tunnel = Self {
            name,
            index: 0,
            up_at: Instant::now(),
            child,
            name_file,
        };
        match tunnel.configure(tools, conf, endpoint).await {
            Ok(index) => {
                tunnel.index = index;
                Ok(tunnel)
            }
            Err(e) => {
                tunnel.down().await;
                Err(e)
            }
        }
    }

    async fn configure(&self, tools: &Tools, conf: &Conf, endpoint: Ipv4Addr) -> io::Result<u16> {
        let name = self.name.as_str();
        let index = route::if_index(name)?;
        let text = conf.setconf(endpoint);
        command::run(
            &tools.awg,
            &["setconf", name, "/dev/stdin"],
            Some(text.as_bytes()),
            STEP,
        )
        .await?;
        let addr = conf.address.to_string();
        let mtu = conf.mtu.to_string();
        command::run(IFCONFIG, &[name, "inet", &addr, &addr, "alias"], None, STEP).await?;
        command::run(IFCONFIG, &[name, "mtu", &mtu], None, STEP).await?;
        command::run(IFCONFIG, &[name, "up"], None, STEP).await?;
        // Seen only by sockets bound to the interface: probes and tunnel DNS.
        command::run(
            ROUTE,
            &[
                "-q",
                "-n",
                "add",
                "-inet",
                "default",
                "-interface",
                name,
                "-ifscope",
                name,
            ],
            None,
            STEP,
        )
        .await?;
        Ok(index)
    }

    /// The UDP port amneziawg-go sends from.
    pub async fn listen_port(&self, tools: &Tools) -> Option<u16> {
        command::run(&tools.awg, &["show", &self.name, "listen-port"], None, STEP)
            .await
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Seconds since the last handshake with the server; None when there
    /// was none, or awg did not say.
    pub async fn handshake_age(&self, tools: &Tools) -> Option<u64> {
        let out = command::run(
            &tools.awg,
            &["show", &self.name, "latest-handshakes"],
            None,
            STEP,
        )
        .await
        .ok()?;
        let at: u64 = out.split_whitespace().nth(1)?.parse().ok()?;
        (at > 0).then(|| crate::state::now().saturating_sub(at))
    }

    /// True once amneziawg-go is gone.
    pub fn exited(&mut self) -> bool {
        !matches!(self.child.try_wait(), Ok(None))
    }

    /// Stops amneziawg-go, which takes the interface with it.
    pub async fn down(mut self) {
        // A process that is gone took its interface along, and the name may
        // already belong to a new tunnel: the scoped route is not ours then.
        if !self.exited() {
            let name = self.name.as_str();
            let _ = command::run(
                ROUTE,
                &["-q", "-n", "delete", "-inet", "default", "-ifscope", name],
                None,
                STEP,
            )
            .await;
        }
        // TERM lets it remove its socket; KILL only if it does not go.
        if let Some(pid) = self.child.id() {
            let _ = command::run("/bin/kill", &["-TERM", &pid.to_string()], None, STEP).await;
        }
        if timeout(Duration::from_secs(3), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
        let _ = std::fs::remove_file(&self.name_file);
    }
}

/// Every amneziawg-go started as this module starts it: those of a daemon
/// that died, when asked before the tunnels of this one are up.
pub async fn stray_pids(tools: &Tools) -> Vec<u32> {
    let pattern = format!("{} -f utun", tools.go.display());
    // pgrep fails when there is none.
    let Ok(out) = command::run("/usr/bin/pgrep", &["-f", "-x", &pattern], None, STEP).await else {
        return Vec::new();
    };
    out.split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect()
}

pub async fn stop_pids(pids: &[u32]) {
    for p in pids {
        let _ = command::run("/bin/kill", &["-TERM", &p.to_string()], None, STEP).await;
    }
}

/// Stops every amneziawg-go started as this module starts it. Returns their
/// pids.
pub async fn kill_strays(tools: &Tools) -> Vec<u32> {
    let pids = stray_pids(tools).await;
    stop_pids(&pids).await;
    pids
}

/// Waits for the interface name amneziawg-go writes, then for its control
/// socket: the name comes first, and `awg setconf` needs the socket.
async fn wait_ready(child: &mut Child, file: &Path, run_dir: &Path) -> io::Result<String> {
    let mut name = None;
    for _ in 0..50 {
        if name.is_none() {
            name = std::fs::read_to_string(file)
                .ok()
                .map(|t| t.trim().to_owned())
                .filter(|n| !n.is_empty());
        }
        if let Some(n) = &name
            && run_dir.join(format!("{n}.sock")).exists()
        {
            return Ok(n.clone());
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!("amneziawg-go exited: {status}")));
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("amneziawg-go not ready, interface {name:?}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "\
[Interface]
PrivateKey = cHJpdmF0ZQ==
Table = off
Address = 10.7.0.2/32, fd00::2/128
MTU = 1280
DNS = 1.1.1.1
Jc = 5
I1 = <b 0x1234>
PostUp = echo hi # a hook

[Peer]
PublicKey = cHVibGlj
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.7:51820
PersistentKeepalive = 25
";

    #[test]
    fn splits_quick_keys_from_setconf() {
        let c = Conf::parse(FILE).unwrap();
        assert_eq!(c.address, Ipv4Addr::new(10, 7, 0, 2));
        assert_eq!(c.mtu, 1280);
        assert_eq!(c.endpoint_ip(), Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(c.endpoint_port, 51820);
        assert_eq!(c.ignored, vec!["table", "dns", "postup"]);
        let text = c.setconf(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            text,
            "[Interface]\nPrivateKey = cHJpdmF0ZQ==\nJc = 5\nI1 = <b 0x1234>\n\
             [Peer]\nPublicKey = cHVibGlj\nAllowedIPs = 0.0.0.0/0\n\
             Endpoint = 198.51.100.1:51820\nPersistentKeepalive = 25\n"
        );
    }

    #[test]
    fn named_endpoint_and_defaults() {
        let c =
            Conf::parse("[Interface]\nAddress = 10.0.0.2\n[Peer]\nEndpoint = vpn.example:51820\n")
                .unwrap();
        assert_eq!(c.endpoint_host, "vpn.example");
        assert_eq!(c.endpoint_ip(), None);
        assert_eq!(c.mtu, 1280);
    }

    #[test]
    fn rejects_incomplete_files() {
        assert!(Conf::parse("[Interface]\nAddress = 10.0.0.2\n").is_err());
        assert!(Conf::parse("[Peer]\nEndpoint = 1.2.3.4:5\n").is_err());
        assert!(
            Conf::parse("[Interface]\nAddress = 10.0.0.2\nMTU = x\n[Peer]\nEndpoint = 1.2.3.4:5\n")
                .is_err()
        );
        assert!(Conf::parse("[Interface]\nAddress = 10.0.0.2\nnonsense\n").is_err());
        assert!(
            Conf::parse(
                "[Interface]\nAddress = 10.0.0.2\n[Peer]\nEndpoint = 1.2.3.4:5\n[Peer]\nEndpoint = 1.2.3.5:5\n"
            )
            .is_err()
        );
    }
}
